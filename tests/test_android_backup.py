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

from vulcanary import _android_backup as backup, _android_manifest as axml, apk_inspection as apk
from test_android_resources import pool, table, REFERENCE
from test_apk_inspection import binary_manifest


def xml(root):
    values = []
    def intern(value):
        if value not in values:
            values.append(value)
        return values.index(value)
    def node(kind, body):
        return struct.pack('<HHIII', kind, 16, 16 + len(body), 1, axml.NONE) + body
    def element(item):
        name, attrs, children = item
        ident = intern(name)
        encoded = []
        for key, value in attrs.items():
            key_id = intern(key)
            kind, number = (0x12, int(value)) if isinstance(value, bool) else (3, intern(value))
            encoded.append(struct.pack('<IIIHBBI', axml.NONE, key_id, axml.NONE, 8, 0, kind, number))
        result = node(0x102, struct.pack('<II6H', axml.NONE, ident, 20, 20, len(attrs), 0, 0, 0) + b''.join(encoded))
        result += b''.join(element(child) for child in children)
        return result + node(0x103, struct.pack('<II', axml.NONE, ident))
    body = element(root)
    body = pool(values) + body
    return struct.pack('<HHI', 3, 8, 8 + len(body)) + body


def exclude(path='secret-fixture.xml', domain='sharedpref', name='exclude'):
    return (name, {'domain': domain, 'path': path}, [])


def legacy(*children):
    return xml(('full-backup-content', {}, list(children)))


def modern(cloud=(), device=()):
    return xml(('data-extraction-rules', {}, [('cloud-backup', {}, list(cloud)),
                                             ('device-transfer', {}, list(device))]))


def request(mode='legacy', path='secret-fixture.xml', domain='sharedpref'):
    return {'mode': mode, 'domain': domain, 'path': path}


class AndroidBackupTests(unittest.TestCase):
    def test_legacy_exact_domain_wide_and_include_negative(self):
        for entry, expected in ((exclude(), 'PASS'), (exclude('.'), 'PASS'),
                                (exclude('./'), 'PASS'), (exclude('other.xml'), 'FAIL'),
                                (exclude(domain='file'), 'FAIL'), (exclude(name='include'), 'FAIL')):
            parsed = backup.parse(legacy(entry), 'fullBackupContent')
            rows = backup.evaluate([request()], {'fullBackupContent': parsed})
            self.assertEqual(rows[0]['state'], expected)

    def test_cloud_and_device_are_independent(self):
        parsed = backup.parse(modern(cloud=[exclude()]), 'dataExtractionRules')
        rows = backup.evaluate([request('cloud'), request('device'), request()], {'dataExtractionRules': parsed})
        self.assertEqual([r['state'] for r in rows], ['PASS', 'FAIL', 'BLOCKED'])
        absent = xml(('data-extraction-rules', {}, [('cloud-backup', {}, [exclude()])]))
        parsed = backup.parse(absent, 'dataExtractionRules')
        self.assertEqual(backup.evaluate([request('device')], {'dataExtractionRules': parsed})[0]['state'], 'FAIL')

    def test_unsupported_document_never_yields_partial_success(self):
        invalid = [legacy(exclude(), ('unknown', {}, [])), legacy(exclude('../private')),
                   legacy(exclude('keys/*')), legacy(('exclude', {'domain': 'sharedpref'}, [])),
                   legacy(('exclude', {'domain': 'sharedpref', 'path': '.', 'requireFlags': 'clientSideEncryption'}, [])),
                   xml(('data-extraction-rules', {}, [('cloud-backup', {}, []), ('cloud-backup', {}, [])])),
                   xml(('data-extraction-rules', {}, [('cross-platform-transfer', {}, [])])),
                   legacy(('include', {'domain': 'sharedpref', 'path': '.', 'requireFlags': 'unknown'}, [])),
                   legacy(('exclude', {'domain': 'sharedpref', 'path': '.'}, [exclude()]))]
        for data in invalid:
            with self.assertRaises(axml.ManifestError):
                backup.parse(data, 'dataExtractionRules' if b'data-extraction-rules' in data else 'fullBackupContent')
        with self.assertRaises(axml.ManifestError):
            backup.parse(legacy(exclude()), 'dataExtractionRules')

    def test_valid_conditions_do_not_replace_explicit_exclusions(self):
        data = legacy(('include', {'domain': 'sharedpref', 'path': '.',
                                  'requireFlags': 'clientSideEncryption|deviceToDeviceTransfer'}, []))
        parsed = backup.parse(data, 'fullBackupContent')
        self.assertEqual(backup.evaluate([request()], {'fullBackupContent': parsed})[0]['state'], 'FAIL')
        data = xml(('data-extraction-rules', {}, [('cloud-backup', {'disableIfNoEncryptionCapabilities': True}, [exclude()])]))
        self.assertIn(('sharedpref', 'secret-fixture.xml'), backup.parse(data, 'dataExtractionRules')['cloud'])

    def test_requirements_fail_closed_and_are_bounded(self):
        for value in ([], {}, [request()] * 2, [request(path='../secret')], [request(mode='unknown')],
                      [request(domain=[])], [dict(request(), id='private')], [request(path='x' * 513)],
                      [request(path=str(i)) for i in range(129)]):
            with self.assertRaises(axml.ManifestError):
                backup.requirements(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'requirements.json'
            for data in (b'[' * 70000, b'[{"mode":"legacy","mode":"cloud","domain":"file","path":"."}]'):
                path.write_bytes(data)
                with self.assertRaises(axml.ManifestError):
                    backup.read_requirements(path)

    def test_apk_evidence_is_sanitized_bound_and_never_runtime_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'candidate.apk'
            content = legacy(exclude())
            manifest = binary_manifest({'debuggable': False, 'allowBackup': False, 'fullBackupContent': None})
            manifest = manifest.replace(struct.pack('<I', 0x7f000001), struct.pack('<I', REFERENCE))
            def write(data):
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr('AndroidManifest.xml', manifest)
                    archive.writestr('resources.arsc', table())
                    archive.writestr('res/xml/private-backup.xml', data)
            write(content)
            report = apk.inspect(path, backup_requirements=[request()])
            self.assertEqual(report['backup_assertions'][0]['state'], 'PASS')
            self.assertIs(report['backup_assertions'][0]['observed'], True)
            self.assertEqual(report['state'], 'BLOCKED')
            self.assertEqual(report['backup_resources'][0]['member_sha256'], hashlib.sha256(content).hexdigest())
            self.assertEqual(report['backup_requirements_sha256'], backup.digest([request()]))
            apk.export(report, Path(directory)/'review')
            for output in (Path(directory)/'review').iterdir():
                for private in ('secret-fixture', 'private-backup', directory, 'private_key_name'):
                    self.assertNotIn(private, output.read_text())
            requested = Path(directory)/'requirements.json'
            requested.write_text(json.dumps([request()]))
            with contextlib.redirect_stdout(io.StringIO()):
                code = apk.main(['--apk', str(path), '--backup-requirements', str(requested),
                                 '--output', str(Path(directory)/'cli-review')])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads((Path(directory)/'cli-review/report.json').read_text())
                             ['backup_assertions'][0]['state'], 'PASS')
            write(legacy(exclude(), ('unknown', {}, [])))
            report = apk.inspect(path, backup_requirements=[request()])
            self.assertEqual(report['backup_assertions'][0]['state'], 'BLOCKED')
            self.assertEqual(report['backup_resources'][0]['resolution'], 'resolved_file')
            with patch.object(apk, 'read_artifact', side_effect=UserWarning('secret-fixture')):
                report = apk.inspect(path, backup_requirements=[request()])
            self.assertIsNone(report['artifact_sha256'])
            self.assertEqual(report['backup_assertions'][0]['state'], 'BLOCKED')

    def test_cli_invalid_requirements_are_source_free(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bad.json'
            path.write_text('{"secret-fixture": true}')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = apk.main(['--apk', str(Path(directory)/'missing.apk'), '--output', str(Path(directory)/'out'),
                                 '--backup-requirements', str(path)])
            self.assertEqual(code, 2)
            self.assertNotIn('secret-fixture', output.getvalue())
            self.assertFalse((Path(directory)/'out').exists())

    def test_rule_mutations_do_not_crash_or_hang(self):
        rng, original = random.Random(6601), legacy(exclude())
        for trial in range(3000):
            data = bytearray(original)
            offset = rng.randrange(len(data))
            if trial % 3 == 0:
                del data[offset:]
            elif trial % 3 == 1:
                data[offset] ^= rng.randrange(1, 256)
            else:
                data[offset:offset] = rng.randbytes(20)
            try:
                result = backup.parse(bytes(data), 'fullBackupContent')
                self.assertEqual(set(result), {'legacy', 'cloud', 'device'})
            except (axml.ManifestError, UnicodeDecodeError):
                pass


if __name__ == '__main__':
    unittest.main()
