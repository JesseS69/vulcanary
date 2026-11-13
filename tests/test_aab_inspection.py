import contextlib
import hashlib
import io
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from vulcanary import aab_inspection as aab, apk_inspection as apk
from vulcanary import _android_proto as proto, _android_manifest as axml
from test_android_backup import request


# Test encoder follows AAPT2 Resources.proto field numbers independently of
# production decoding. No app payload or executable archive members are needed.
def varint(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    return bytes(out + bytes([n]))


def number(field, value):
    return varint(field << 3) + varint(value)


def blob(field, value):
    if isinstance(value, str):
        value = value.encode()
    return varint(field << 3 | 2) + varint(len(value)) + value


def attr(name, value, ns='', ident=0, compiled=None):
    data = blob(1, ns) + blob(2, name) + blob(3, value)
    if ident:
        data += number(5, ident)
    if compiled is not None:
        data += blob(6, compiled)
    return data


def element(name, attrs=(), children=(), ns=''):
    return blob(1, blob(2, ns) + blob(3, name) + b''.join(blob(4, a) for a in attrs)
                + b''.join(blob(5, c) for c in children))


def boolean(name, value):
    return attr(name, str(value).lower(), axml.ANDROID, axml.ATTRIBUTES[name],
                blob(7, number(8, int(value))))


REF = 0x7f010000
def manifest(extra=(), flags=True):
    attrs = [boolean('debuggable', False), boolean('allowBackup', False)] if flags else []
    attrs += [attr('fullBackupContent', '@xml/fixture', axml.ANDROID,
                   axml.BACKUP_ATTRIBUTES['fullBackupContent'], blob(1, number(2, REF)))]
    return element('manifest', children=[element('application', attrs=attrs + list(extra))])


def resource(path='res/xml/fixture.xml', configs=None, item=None):
    item = blob(5, blob(1, path) + number(2, 3)) if item is None else item
    config = blob(2, blob(4, item))
    configs = [config] if configs is None else configs
    entry = blob(1, b'') + blob(2, 'fixture') + b''.join(blob(6, c) for c in configs)
    typ = blob(1, number(1, 1)) + blob(2, 'xml') + blob(3, entry)
    package = blob(1, number(1, 127)) + blob(2, 'synthetic.example') + blob(3, typ)
    return blob(2, package)


def rules(path='private.xml'):
    return element('full-backup-content', children=[element('exclude',
        [attr('domain', 'sharedpref'), attr('path', path)])])


def bundle(path, man=None, table=None, rule=None, extra=()):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in [('BundleConfig.pb', b'\x0a\x00'),
                           ('base/manifest/AndroidManifest.xml', manifest() if man is None else man),
                           ('base/resources.pb', resource() if table is None else table),
                           ('base/res/xml/fixture.xml', rules() if rule is None else rule), *extra]:
            archive.writestr(name, data)


class AabInspectionTests(unittest.TestCase):
    def test_android_sdk_compiled_fixture_not_our_encoder(self):
        root = Path(__file__).parent/'fixtures/aab/compiled'
        pins = {
            'AndroidManifest.xml':'84ae76049afdf8efbcd69ac70631cee17df8b97a4036b681e5b34a9821b1757c',
            'resources.pb':'c5be13b333d7fa57958d1ee455eb64ea644c40f26b79e434c2820f22c858be41',
            'backup.xml':'67e2becd659abc53ef54e9311116da025550ae3afe85e856d9301086aa128152',
            'extraction.xml':'f2750e1615a40b5ed2f54406dcde98059af4e6dbf6ed8f07f9417555964181bc',
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'sdk-fixture.aab'
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('BundleConfig.pb',b'\x0a\x00')
                for name, pin in pins.items():
                    data = (root/name).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(),pin)
                    prefix = 'base/manifest/' if name == 'AndroidManifest.xml' else 'base/' if name == 'resources.pb' else 'base/res/xml/'
                    archive.writestr(prefix+name,data)
            req = [request(mode,'fixture.xml') for mode in ('legacy','cloud','device')]
            req += [request(path='sample.db-wal',domain='database')]
            report = aab.inspect(path,backup_requirements=req)
            self.assertIsNotNone(report['artifact_sha256'])
            self.assertEqual([r['state'] for r in report['backup_assertions']],['BLOCKED','BLOCKED','PASS','BLOCKED'])
            self.assertEqual([r['observed'] for r in report['checks'][:2]],[False,True])

    def test_protobuf_wire_known_bytes_and_malformed_inputs(self):
        self.assertEqual(proto.Decoder().message(bytes.fromhex('0801120178'), {1:0, 2:2}), {1:1, 2:b'x'})
        for data in (b'\x00', b'\x08\x80', b'\x08\x80\x00', b'\x12\x05x',
                     b'\x08\x01\x08\x00', b'\x0b', b'\x08'+b'\xff'*10,
                     b'\x18\x01'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                proto.Decoder().message(data, {1:0, 2:2})

    def test_real_archive_identity_flags_links_and_cli_privacy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root/'private-candidate.aab'
            bundle(path)
            req = [request(path='private.xml')]
            report = aab.inspect(path, backup_requirements=req)
            self.assertEqual(report['schema'], 'vulcanary.aab-manifest-inspection.v1')
            self.assertEqual(report['artifact_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual([r['state'] for r in report['checks']], ['PASS','PASS','BLOCKED'])
            self.assertEqual(report['backup_assertion_counts'], {'PASS':1,'FAIL':0,'BLOCKED':0})
            self.assertEqual(report['backup_resources'][0]['member_sha256'], hashlib.sha256(rules()).hexdigest())
            requirements = root/'requirements.json'
            requirements.write_text(json.dumps(req))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = aab.main(['--aab',str(path),'--output',str(root/'report'),
                                 '--backup-requirements',str(requirements)])
            self.assertEqual(code, 2)
            for file in (root/'report').iterdir():
                for secret in ('private.xml','synthetic.example','private-candidate',temp):
                    self.assertNotIn(secret, file.read_text())
            self.assertIn('# AAB', (root/'report/reviewer.md').read_text())
            self.assertIsNone(apk.inspect(path)['artifact_sha256'])
            for rule, expected in ((rules('private'),'BLOCKED'),(rules('other.xml'),'FAIL')):
                bundle(path,rule=rule)
                self.assertEqual(aab.inspect(path,backup_requirements=req)['backup_assertions'][0]['state'],expected)

    def test_manifest_defaults_ambiguity_and_compiled_truth(self):
        self.assertNotIn('allowBackup',proto.Decoder().manifest(manifest(flags=False)))
        for bad in (manifest([boolean('allowBackup',True)]),
                    element('manifest',children=[element('application'),element('application')]),
                    element('manifest',children=[element('application',attrs=[attr('allowBackup','false',axml.ANDROID,axml.ATTRIBUTES['allowBackup'],blob(7,number(8,1)))])]),
                    element('manifest',children=[element('application',attrs=[attr('wrong','false',axml.ANDROID,axml.ATTRIBUTES['allowBackup'])])]),
                    manifest()+blob(2,'ambiguous')):
            with self.assertRaises(ValueError):
                proto.Decoder().manifest(bad)
        ref = attr('allowBackup','@bool/test',axml.ANDROID,axml.ATTRIBUTES['allowBackup'],blob(1,number(2,REF)))
        self.assertIsNone(proto.Decoder().manifest(element('manifest',children=[element('application',[ref])]))['allowBackup'])

    def test_resource_configs_aliases_unknown_fields_and_paths_refused(self):
        for data in (resource('../private.xml'), resource('res/../private.xml'),
                     resource(configs=[blob(1,b'\x08\x01')+blob(2,blob(4,blob(5,blob(1,'res/x.xml')+number(2,3))))]),
                     resource(configs=[]), resource(item=blob(1,number(2,REF))),
                     resource()+blob(3,b''), resource()+resource()):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                proto.Decoder().resolve_xml(data,REF)

    def test_limits_and_deep_or_large_xml_refused(self):
        for limit, value, operation in (
            ('MAX_FIELDS',1,lambda:proto.Decoder().manifest(manifest())),
            ('MAX_TEXT',3,lambda:proto.Decoder().manifest(manifest())),
            ('MAX_NODES',1,lambda:proto.Decoder().manifest(manifest())),
            ('MAX_DEPTH',1,lambda:proto.Decoder().manifest(manifest()))):
            with patch.object(proto,limit,value), self.assertRaises(ValueError):
                operation()
        nested=element('child')
        for _ in range(65):
            nested=element('child',children=[nested])
        with self.assertRaises(ValueError):
            proto.Decoder().xml(nested)

    def test_archive_modules_warnings_and_malformed_rules_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'sample.aab'
            for extra in ([('feature/manifest/AndroidManifest.xml',manifest())],
                          [('feature/resources.pb',resource())], [('AndroidManifest.xml',b'x')]):
                bundle(path,extra=extra)
                self.assertIsNone(aab.inspect(path)['artifact_sha256'])
            bundle(path,rule=rules()+blob(2,'ambiguous'))
            report=aab.inspect(path,backup_requirements=[request(path='private.xml')])
            self.assertEqual(report['backup_assertion_counts']['BLOCKED'],1)
            self.assertIsNotNone(report['artifact_sha256'])
            with patch.object(apk,'read_member',side_effect=UserWarning('PRIVATE_MEMBER')):
                self.assertIsNone(aab.inspect(path)['artifact_sha256'])

    def test_seeded_protobuf_mutations_never_crash(self):
        rng=random.Random(20261112)
        seeds=[manifest(),resource(),rules()]
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'sample.aab'
            for _ in range(120):
                index=rng.randrange(3)
                changed=bytearray(seeds[index])
                where=rng.randrange(len(changed))
                if rng.randrange(2):
                    changed[where]=rng.randrange(256)
                else:
                    del changed[where:]
                data=list(seeds)
                data[index]=bytes(changed)
                bundle(path,man=data[0],table=data[1],rule=data[2])
                report=aab.inspect(path,backup_requirements=[request(path='private.xml')])
                self.assertEqual(report['state'],'BLOCKED')
                self.assertNotIn('private.xml',json.dumps(report))


if __name__ == '__main__':
    unittest.main()
