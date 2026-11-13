import hashlib
import json
from pathlib import Path
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from vulcanary import android_apk_collection as copy
from vulcanary import android_inventory as inv
from test_android_inventory import response, NONCE, PACKAGE, SERIAL

REMOTE = '/data/app/~~random/' + PACKAGE + '-random/base.apk'
DATA = b'PK synthetic private code bytes'
OBS = {'version_code':31,'apk_path_count':1,'apk_path_sha256':[inv.digest(REMOTE)],'matching_package_snapshots':True}
EXPECTED = {'schema':'vulcanary.android-readonly-inventory.v1','state':'NOT_RUN','collection_state':'COMPLETE',
            'device_selector_sha256':inv.digest(SERIAL),'application_id_sha256':inv.digest(PACKAGE),'android_user':0,'observations':OBS}


class SyncServer:
    def __init__(self, fault=None):
        self.fault = fault
        self.events = []
        self.errors = []
        self.transferred = False
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1',0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.thread = threading.Thread(target=self.run)

    def read(self, s, n):
        result = b''
        while len(result)<n:
            data=s.recv(n-len(result))
            if not data:raise EOFError()
            result+=data
        return result

    def run(self):
        try:
            with self.listener.accept()[0] as s:
                s.settimeout(3)
                for _ in range(2):
                    value=self.read(s,int(self.read(s,4),16)).decode()
                    self.events.append(value)
                    s.sendall(b'OKAY')
                while True:
                    kind,n=struct.unpack('<4sI',self.read(s,8))
                    path=self.read(s,n).decode()
                    self.events.append((kind,path))
                    if kind==b'LST2':
                        mode=stat.S_IFREG|0o644 if path==REMOTE else stat.S_IFDIR|0o755
                        size=len(DATA) if path==REMOTE else 4096
                        if self.fault=='symlink' and path==REMOTE:mode=stat.S_IFLNK|0o777
                        if self.fault=='parent_symlink' and path=='/data/app/~~random':mode=stat.S_IFLNK|0o777
                        if self.fault=='oversize' and path==REMOTE:size=copy.MAX_FILE+1
                        mtime=2 if self.fault=='changed' and self.transferred and path==REMOTE else 1
                        s.sendall(copy.STAT.pack(b'LST2',0,1,1,mode,1,1000,1000,size,1,mtime,1))
                    elif kind==b'RECV':
                        self.transferred=True
                        if self.fault=='slow':time.sleep(.2)
                        if self.fault=='fail':s.sendall(struct.pack('<4sI',b'FAIL',6)+b'SECRET');return
                        if self.fault=='huge_frame':s.sendall(struct.pack('<4sI',b'DATA',65537));return
                        if self.fault=='zero_frame':s.sendall(struct.pack('<4sI',b'DATA',0));return
                        if self.fault=='short':s.sendall(struct.pack('<4sI',b'DONE',0));continue
                        payload=DATA if self.fault!='long' else DATA+b'X'
                        s.sendall(struct.pack('<4sI',b'DATA',len(payload))+payload)
                        if self.fault=='disconnect':return
                        s.sendall(struct.pack('<4sI',b'DONE',0))
                        if self.fault=='trailing':s.sendall(struct.pack('<4sI',b'DATA',1)+b'x')
                    else:raise ValueError('unexpected service')
        except (EOFError,BrokenPipeError,ConnectionResetError,ConnectionAbortedError):pass
        except Exception as e:self.errors.append(type(e).__name__)
        finally:self.listener.close()

    def __enter__(self):self.thread.start();return self
    def __exit__(self,*args):
        self.thread.join(4)
        if self.thread.is_alive() or self.errors:raise RuntimeError(str(self.errors))


class ApkCollectionTests(unittest.TestCase):
    def run_copy(self, root, server, **kwargs):
        with patch.object(copy,'snapshot',return_value=(OBS,[REMOTE])):
            return copy.collect(SERIAL,PACKAGE,EXPECTED,root,user=0,port=server.port,
                                authorized=True,trust_existing_server=True,**kwargs)

    def test_real_sync_protocol_collects_hashes_not_security_pass(self):
        with tempfile.TemporaryDirectory() as t, SyncServer() as s:
            root=Path(t)/'out'
            report=self.run_copy(root,s)
            self.assertEqual(report['collection_state'],'COMPLETE')
            self.assertEqual(report['state'],'NOT_RUN')
            self.assertEqual((root/'artifact-000.apk').read_bytes(),DATA)
            self.assertEqual(report['artifacts'][0]['sha256'],hashlib.sha256(DATA).hexdigest())
            self.assertEqual(s.events[:2],['host:transport:'+SERIAL,'sync:'])
            self.assertEqual([x for x in s.events[2:] if x[0]==b'RECV'],[(b'RECV',REMOTE)])
            self.assertTrue(all(x[0] in (b'LST2',b'RECV') for x in s.events[2:]))
            text=(root/'report.json').read_text()
            for secret in (SERIAL,PACKAGE,REMOTE,'SECRET',DATA.decode()):self.assertNotIn(secret,text)
            self.assertFalse(list(root.glob('*.partial')))

    def test_failures_discard_partial_bytes_and_all_artifact_claims(self):
        for fault in ('symlink','parent_symlink','oversize','changed','fail','huge_frame','zero_frame','short','long','disconnect','trailing','slow'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as t,SyncServer(fault) as s:
                root=Path(t)/'out'
                report=self.run_copy(root,s,timeout=.08 if fault=='slow' else 2)
                self.assertEqual(report['collection_state'],'BLOCKED')
                self.assertEqual(report['artifacts'],[])
                self.assertIsNone(report['observations'])
                self.assertFalse(list(root.glob('*.apk'))+list(root.glob('*.partial')))
                if fault in ('symlink','parent_symlink','oversize'):
                    self.assertFalse(any(isinstance(x,tuple) and x[0]==b'RECV' for x in s.events))

    def test_authorization_and_changed_scope_refuse_before_socket(self):
        with tempfile.TemporaryDirectory() as t,patch.object(copy.socket,'socket',side_effect=AssertionError('must not connect')):
            root=Path(t)/'out'
            r=copy.collect(SERIAL,PACKAGE,EXPECTED,root)
            self.assertEqual(r['reason'],'authorization_required')
            self.assertFalse(root.exists())
            for change in ({'device_selector_sha256':'0'*64},{'application_id_sha256':'0'*64},{'android_user':10}):
                r=copy.collect(SERIAL,PACKAGE,{**EXPECTED,**change},root,authorized=True,trust_existing_server=True)
                self.assertEqual(r['state'],'BLOCKED');self.assertFalse(root.exists())

    def test_existing_output_is_never_removed(self):
        with tempfile.TemporaryDirectory() as t,patch.object(copy.socket,'socket',side_effect=AssertionError('must not connect')):
            root=Path(t);(root/'keep').write_bytes(b'important')
            r=copy.collect(SERIAL,PACKAGE,EXPECTED,root,authorized=True,trust_existing_server=True)
            self.assertEqual(r['state'],'BLOCKED');self.assertEqual((root/'keep').read_bytes(),b'important')

    def test_fresh_inventory_must_equal_approved_and_final_snapshot(self):
        for changed_index in (0,1):
            with tempfile.TemporaryDirectory() as t,SyncServer() as s:
                values=[(OBS,[REMOTE]),(OBS,[REMOTE])]
                values[changed_index]=({**OBS,'version_code':32},[REMOTE])
                root=Path(t)/'out'
                with patch.object(copy,'snapshot',side_effect=values):
                    r=copy.collect(SERIAL,PACKAGE,EXPECTED,root,port=s.port,authorized=True,trust_existing_server=True)
                self.assertEqual(r['state'],'BLOCKED');self.assertFalse(list(root.glob('*.apk'))+list(root.glob('*.partial')))

    def test_path_allowlist_requires_exact_package_code_layout(self):
        raw=response().replace(b'package:/data/app/private/base.apk\npackage:/data/app/private/split.apk',('package:'+REMOTE).encode())
        self.assertEqual(copy.paths_from(raw,NONCE,PACKAGE)[1],[REMOTE])
        for bad in ('/data/data/'+PACKAGE+'/secret.apk','/sdcard/base.apk',REMOTE.replace(PACKAGE,'org.other'),
                    REMOTE.replace('base.apk','secret.apk'),REMOTE.replace('~~random','../escape'),REMOTE.replace('~~random','symlink;id')):
            with self.assertRaises(ValueError):copy.paths_from(raw.replace(REMOTE.encode(),bad.encode()),NONCE,PACKAGE)

    def test_aggregate_size_and_frame_budgets_fail_closed(self):
        with tempfile.TemporaryDirectory() as t,SyncServer() as s,patch.object(copy,'MAX_TOTAL',len(DATA)-1):
            report=self.run_copy(Path(t)/'out',s)
            self.assertEqual(report['state'],'BLOCKED')
            self.assertFalse(any(isinstance(x,tuple) and x[0]==b'RECV' for x in s.events))
        with tempfile.TemporaryDirectory() as t,SyncServer() as s,patch.object(copy,'MAX_FRAMES',1):
            root=Path(t)/'out';report=self.run_copy(root,s)
            self.assertEqual(report['state'],'BLOCKED')
            self.assertFalse(list(root.glob('*.partial')))

    def test_cleanup_failure_is_reported_without_artifact_success(self):
        original=Path.unlink
        def refuse_partial(path,*args,**kwargs):
            if path.suffix=='.partial':raise PermissionError('PRIVATE')
            return original(path,*args,**kwargs)
        with tempfile.TemporaryDirectory() as t,SyncServer('changed') as s:
            root=Path(t)/'out'
            with patch.object(Path,'unlink',refuse_partial):report=self.run_copy(root,s)
            self.assertEqual(report['state'],'BLOCKED');self.assertFalse(report['cleanup_complete'])
            self.assertEqual(report['artifacts'],[]);self.assertTrue(list(root.glob('*.partial')))
            self.assertNotIn('PRIVATE',(root/'report.json').read_text())

    def test_local_promotion_failure_discards_the_copy(self):
        with tempfile.TemporaryDirectory() as t,SyncServer() as s,patch.object(Path,'hardlink_to',side_effect=OSError('PRIVATE')):
            root=Path(t)/'out';report=self.run_copy(root,s)
            self.assertEqual(report['state'],'BLOCKED');self.assertTrue(report['cleanup_complete'])
            self.assertFalse(list(root.glob('*.apk'))+list(root.glob('*.partial')))

    def test_local_existing_partial_is_not_owned_or_removed(self):
        class Wire:
            def send(self,data):pass
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'file.partial';path.write_bytes(b'keep')
            owned=[]
            with self.assertRaises(FileExistsError):copy.receive(Wire(),REMOTE,path,1,owned)
            self.assertEqual(owned,[]);self.assertEqual(path.read_bytes(),b'keep')

    def test_real_snapshot_parser_combines_with_sync_collection(self):
        calls=[]
        def metadata(serial,package,user,port,timeout,nonce):
            calls.append((serial,package,user))
            return response(nonce).replace(b'package:/data/app/private/base.apk\npackage:/data/app/private/split.apk',('package:'+REMOTE).encode())
        approved=copy.paths_from(metadata(SERIAL,PACKAGE,0,0,1,NONCE),NONCE,PACKAGE)[0]
        calls.clear()
        with tempfile.TemporaryDirectory() as t,SyncServer() as s,patch.object(inv,'collect',side_effect=metadata):
            report=copy.collect(SERIAL,PACKAGE,{**EXPECTED,'observations':approved},Path(t)/'out',port=s.port,authorized=True,trust_existing_server=True)
        self.assertEqual(report['collection_state'],'COMPLETE')
        self.assertEqual(calls,[(SERIAL,PACKAGE,0)]*2)


if __name__=='__main__':unittest.main()
