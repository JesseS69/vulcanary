import contextlib
import hashlib
import io
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from vulcanary import android_identity as identity
from vulcanary import _android_manifest as axml, _android_proto as proto
from vulcanary import _android_identity_fields as fields
from test_aab_inspection import element, attr, blob, number
from test_apk_inspection import binary_manifest

ROOT = Path(__file__).parent/'fixtures/android-identity'
PINS = {'apk':'dc7dd7d0c553e1d2c42741cfa21a53fd5962b5cef9ddf7b0d0fe45df41ddeb4a',
        'aab':'669890d2b797426c7f199ff5dd5c616595c6b370130ece512204ae18c583e85f'}


def artifact(path, kind, data=None, extra=False):
    if data is None:
        data=(ROOT/('manifest.bin' if kind=='apk' else 'manifest.pb')).read_bytes()
    with zipfile.ZipFile(path,'w') as z:
        z.writestr('AndroidManifest.xml' if kind=='apk' else 'base/manifest/AndroidManifest.xml',data)
        if kind=='aab':
            z.writestr('BundleConfig.pb',b'\x0a\x00')
        if extra:
            z.writestr('base/assets/extra' if kind=='aab' else 'assets/extra',b'changed bytes')


def expected(path, kind):
    return {'schema':'vulcanary.android-identity-expectations.v1','artifact_format':kind,
            'artifact_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'application_id':'org.example.identityfixture','version_name':'2.3-fixture',
            'version_code':(1<<32)|42}


class AndroidIdentityTests(unittest.TestCase):
    def test_independent_sdk_binary_and_protobuf_identity_parity(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'untrusted-name'
            for kind in ('apk','aab'):
                raw=(ROOT/('manifest.bin' if kind=='apk' else 'manifest.pb')).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(),PINS[kind])
                artifact(path,kind)
                report=identity.inspect(path,expected(path,kind))
                self.assertEqual(report['state'],'PASS')
                self.assertEqual(report['counts'],{'PASS':4,'FAIL':0,'BLOCKED':0})
                self.assertEqual(report['checks'][2]['observed'],4294967338)
                self.assertEqual(report['policy_effect'],'none')
                self.assertFalse(report['target_executed'])
                self.assertIn('installed_identity',report['unverified'])

    def test_each_identity_dimension_has_a_negative_control(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'sample'
            for kind in ('apk','aab'):
                artifact(path,kind)
                original=expected(path,kind)
                for key,value in [('artifact_sha256','0'*64),('application_id','org.example.wrong'),
                                  ('version_name','wrong'),('version_code',42)]:
                    report=identity.inspect(path,{**original,key:value})
                    self.assertEqual(report['state'],'FAIL')
                    self.assertEqual(report['counts'],{'PASS':3,'FAIL':1,'BLOCKED':0})
                artifact(path,kind,extra=True)
                report=identity.inspect(path,original)
                self.assertEqual(report['checks'][0]['state'],'FAIL')
                self.assertEqual(report['counts']['PASS'],3)

    def test_missing_and_resource_referenced_values_are_not_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'sample'
            artifact(path,'apk',binary_manifest())
            r=identity.inspect(path,expected(path,'apk'))
            self.assertEqual(r['state'],'BLOCKED')
            self.assertEqual(r['counts'],{'PASS':1,'FAIL':0,'BLOCKED':3})
        attrs=[attr('package','org.example.fixture'),
               attr('versionCode','@integer/code',axml.ANDROID,fields.IDS['versionCode'],blob(1,number(2,1))),
               attr('versionName','@string/name',axml.ANDROID,fields.IDS['versionName'],blob(1,number(2,2)))]
        parsed=proto.Decoder().manifest(element('manifest',attrs,[element('application')]),include_identity=True)['_identity']
        self.assertIsNone(parsed['version_code'])
        self.assertIsNone(parsed['version_name'])

    def test_wrong_ids_duplicate_values_and_conflicting_types_refused(self):
        for attrs in ([attr('versionCode','42',axml.ANDROID,fields.IDS['versionName'],blob(7,number(6,42)))],
                      [attr('versionCode','42',axml.ANDROID,fields.IDS['versionCode'],blob(7,number(6,43)))],
                      [attr('package','x'),attr('package','y')],
                      [attr('versionCode','true',axml.ANDROID,fields.IDS['versionCode'],blob(7,number(8,1)))],
                      [attr('versionCode','42',axml.ANDROID,fields.IDS['versionCode'],blob(2,blob(1,'42')))]):
            with self.assertRaises(ValueError):
                proto.Decoder().manifest(element('manifest',attrs,[element('application')]),include_identity=True)
        raw=(ROOT/'manifest.bin').read_bytes()
        altered=raw.replace(struct.pack('<I',fields.IDS['versionCode']),struct.pack('<I',fields.IDS['versionName']))
        with self.assertRaises(ValueError):
            axml.parse(altered,include_identity=True)

    def test_version_major_default_and_supported_integer_bounds(self):
        base={(axml.ANDROID,'versionCode'):(fields.IDS['versionCode'],42)}
        self.assertEqual(fields.identity(base)['version_code'],42)
        with self.assertRaises(ValueError):
            fields.identity({(axml.ANDROID,'versionCode'):(fields.IDS['versionCode'],True)})
        with self.assertRaises(ValueError):
            fields.identity({(axml.ANDROID,'versionCode'):(fields.IDS['versionCode'],0x80000000)})
        base[(axml.ANDROID,'versionCodeMajor')]=(fields.IDS['versionCodeMajor'],None)
        self.assertIsNone(fields.identity(base)['version_code'])

    def test_cli_exports_sanitized_results_and_refuses_invalid_or_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); path=root/'PRIVATE-PATH.apk'; artifact(path,'apk')
            spec=root/'expected.json'; spec.write_text(json.dumps(expected(path,'apk')))
            for index,(change,wanted) in enumerate((({},0),({'version_code':43},1))):
                spec.write_text(json.dumps({**expected(path,'apk'),**change}))
                output=root/str(index)
                with contextlib.redirect_stdout(io.StringIO()):
                    code=identity.main(['--artifact',str(path),'--expected',str(spec),'--output',str(output)])
                self.assertEqual(code,wanted)
                for f in output.iterdir():
                    for private in ('org.example.identityfixture','2.3-fixture','PRIVATE-PATH',temp):
                        self.assertNotIn(private,f.read_text())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(identity.main(['--artifact',str(path),'--expected',str(spec),'--output',str(root/'0')]),2)
            for bad in ('{"schema":"x","schema":"y"}', ' '*16385, '{"private":"SECRET"}'):
                spec.write_text(bad)
                capture=io.StringIO()
                with contextlib.redirect_stdout(capture):
                    self.assertEqual(identity.main(['--artifact',str(path),'--expected',str(spec),'--output',str(root/'bad')]),2)
                self.assertNotIn('SECRET',capture.getvalue())
                self.assertFalse((root/'bad').exists())

    def test_invalid_expected_types_and_missing_artifact_fail_closed(self):
        spec={'schema':'vulcanary.android-identity-expectations.v1','artifact_format':'apk','artifact_sha256':'0'*64,
              'application_id':'private','version_name':'private','version_code':1}
        for key,value in [('version_code',True),('version_code',-1),('artifact_sha256','not-hex'),
                          ('application_id',''),('version_name','x'*1025),('artifact_format','ipa')]:
            with self.assertRaises(ValueError):
                identity.validate_expected({**spec,key:value})
        self.assertEqual(identity.inspect(Path('missing-identity-fixture.apk'),spec)['state'],'BLOCKED')
        with patch.object(identity.apk,'read_artifact',side_effect=UserWarning('PRIVATE')):
            r=identity.inspect(Path('unused'),spec)
            self.assertIsNone(r['artifact_sha256'])
            self.assertEqual(r['counts']['BLOCKED'],4)

    def test_seeded_mutations_remain_bounded_and_source_free(self):
        rng=random.Random(20261113)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'sample'
            for kind in ('apk','aab'):
                seed=(ROOT/('manifest.bin' if kind=='apk' else 'manifest.pb')).read_bytes()
                for _ in range(80):
                    data=bytearray(seed); index=rng.randrange(len(data))
                    if rng.randrange(2): data[index]=rng.randrange(256)
                    else: del data[index:]
                    artifact(path,kind,bytes(data))
                    r=identity.inspect(path,expected(path,kind))
                    self.assertIn(r['state'],('PASS','FAIL','BLOCKED'))
                    self.assertNotIn('org.example.identityfixture',json.dumps(r))


if __name__=='__main__':
    unittest.main()
