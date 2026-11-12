import hashlib
import io
from contextlib import redirect_stderr
import json
from pathlib import Path
import random
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile

from vulcanary import apk_inspection as apk
from vulcanary import _android_manifest as axml


def binary_manifest(attributes=None, *, utf8=True, wrong_id=False, duplicate=False, raw_conflict=False):
    attributes = {'debuggable': False, 'allowBackup': False} if attributes is None else attributes
    values = ['manifest', 'application', axml.ANDROID, 'android', 'true', 'false', *attributes]
    pool_data, offsets = b'', []
    for value in values:
        offsets.append(len(pool_data))
        encoded = value.encode('utf-8' if utf8 else 'utf-16-le')
        pool_data += (bytes([len(value), len(encoded)]) + encoded + b'\0' if utf8
                      else struct.pack('<H', len(value)) + encoded + b'\0\0')
    pool_data += b'\0' * (-len(pool_data) % 4)
    pool = struct.pack('<HHI5I', 1, 28, 28 + 4*len(values) + len(pool_data), len(values), 0,
                       0x100 if utf8 else 0, 28 + 4*len(values), 0)
    pool += struct.pack('<' + 'I'*len(values), *offsets) + pool_data
    ids = [{**axml.ATTRIBUTES, **axml.BACKUP_ATTRIBUTES}.get(value, 0) for value in values]
    if wrong_id:
        ids[6] += 1
    resources = struct.pack('<HHI', 0x180, 8, 8 + 4*len(ids)) + struct.pack('<' + 'I'*len(ids), *ids)
    def node(kind, body):
        return struct.pack('<HHIII', kind, 16, 16+len(body), 1, axml.NONE) + body
    def start(name, attrs):
        return node(0x102, struct.pack('<II6H', axml.NONE, name, 20, 20, len(attrs), 0, 0, 0) + b''.join(attrs))
    attrs = []
    for name, value in attributes.items():
        attrs.append(struct.pack('<IIIHBBI', 2, values.index(name), 4 if raw_conflict else axml.NONE,
                                 8, 0, 1 if value is None else 0x12,
                                 0x7f000001 if value is None else 0xffffffff if value else 0))
    if duplicate:
        attrs += attrs[:1]
    body = pool + resources + node(0x100, struct.pack('<II', 3, 2))
    body += start(0, []) + start(1, attrs)
    body += node(0x103, struct.pack('<II', axml.NONE, 1)) + node(0x103, struct.pack('<II', axml.NONE, 0))
    body += node(0x101, struct.pack('<II', 3, 2))
    return struct.pack('<HHI', 3, 8, 8+len(body)) + body


class ApkInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root/'candidate.apk'

    def artifact(self, data=None, duplicate=False):
        with zipfile.ZipFile(self.path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('AndroidManifest.xml', binary_manifest() if data is None else data)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    archive.writestr('AndroidManifest.xml', binary_manifest())

    def test_typed_flags_utf8_utf16_and_identity(self):
        for utf8 in (True, False):
            self.artifact(binary_manifest(utf8=utf8))
            result = apk.inspect(self.path)
            self.assertEqual(result['counts'], {'PASS': 2, 'FAIL': 0, 'BLOCKED': 1})
            self.assertEqual(result['state'], 'BLOCKED')
            self.assertEqual(result['artifact_sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
            self.assertEqual([row['observed'] for row in result['checks'][:2]], [False, False])

    def test_enabled_defaults_and_resource_references(self):
        self.artifact(binary_manifest({'debuggable': True, 'allowBackup': True}))
        self.assertEqual(apk.inspect(self.path)['counts']['FAIL'], 2)
        self.artifact(binary_manifest({}))
        result = apk.inspect(self.path)
        self.assertEqual([row['observed'] for row in result['checks'][:2]], [False, True])
        self.assertEqual(result['checks'][0]['basis'], 'android_default')
        self.artifact(binary_manifest({'debuggable': None, 'allowBackup': None}))
        result = apk.inspect(self.path)
        self.assertEqual(result['counts']['BLOCKED'], 3)
        self.assertIsNotNone(result['artifact_sha256'])

    def test_ambiguous_names_ids_raw_values_and_truncated_tree_block(self):
        for data in (binary_manifest(wrong_id=True), binary_manifest(duplicate=True),
                     binary_manifest(raw_conflict=True), binary_manifest()[:-24], b'<manifest/>'):
            self.artifact(data)
            result = apk.inspect(self.path)
            self.assertEqual(result['counts']['BLOCKED'], 3)
            self.assertIsNone(result['artifact_sha256'])

    def test_archive_and_manifest_limits_before_processing(self):
        self.artifact(duplicate=True)
        self.assertEqual(apk.inspect(self.path)['counts']['BLOCKED'], 3)
        self.artifact(b'\0'*(axml.MAX_XML+1))
        with patch.object(axml, 'parse', side_effect=AssertionError('must not parse')):
            self.assertIsNone(apk.inspect(self.path)['artifact_sha256'])
        self.artifact()
        with patch.object(apk, 'MAX_ENTRIES', 0), patch.object(apk.zipfile, 'ZipFile', side_effect=AssertionError('must not allocate')):
            self.assertIsNone(apk.inspect(self.path)['artifact_sha256'])
        with patch.object(apk, 'MAX_ARTIFACT_BYTES', 3):
            self.assertIsNone(apk.inspect(self.path)['artifact_sha256'])

    def test_central_directory_count_lie_rejected_before_zipfile(self):
        with zipfile.ZipFile(self.path, 'w') as archive:
            archive.writestr('AndroidManifest.xml', binary_manifest())
            archive.writestr('extra', b'ignored')
        raw = bytearray(self.path.read_bytes())
        end = raw.rfind(b'PK\x05\x06')
        struct.pack_into('<HH', raw, end + 8, 1, 1)
        self.path.write_bytes(raw)
        with patch.object(apk.zipfile, 'ZipFile', side_effect=AssertionError('must not allocate')):
            self.assertIsNone(apk.inspect(self.path)['artifact_sha256'])

    def test_changed_handle_blocks_identity_and_windows_ctime_skew_does_not(self):
        self.artifact()
        before = self.path.stat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')
        after = SimpleNamespace(**{key: getattr(before, key) for key in fields})
        after.st_mtime_ns += 1
        with patch.object(apk.os, 'fstat', side_effect=[before, after]):
            self.assertIsNone(apk.inspect(self.path)['artifact_sha256'])
        after.st_mtime_ns = before.st_mtime_ns
        after.st_ctime_ns += 1
        with patch.object(apk.os, 'fstat', return_value=after):
            self.assertIsNotNone(apk.inspect(self.path)['artifact_sha256'])

    def test_seeded_malformed_binary_mutations_never_crash(self):
        rng = random.Random(91)
        original = binary_manifest()
        for _ in range(200):
            data = bytearray(original)
            index = rng.randrange(len(data))
            if rng.randrange(2):
                data[index] ^= rng.randrange(1, 256)
            else:
                del data[index:]
            self.artifact(bytes(data))
            report = apk.inspect(self.path)
            self.assertEqual(report['state'], 'BLOCKED')
            self.assertEqual(sum(report['counts'].values()), 3)

    def test_cli_exports_no_source_and_refuses_overwrite(self):
        self.artifact()
        args = ['--apk', str(self.path), '--output', str(self.root/'review')]
        self.assertEqual(apk.main(args), 2)
        for file in (self.root/'review').iterdir():
            self.assertNotIn(str(self.root), file.read_text())
            self.assertNotIn(axml.ANDROID, file.read_text())
        with patch.object(apk, 'inspect', side_effect=AssertionError('must not inspect')):
            self.assertEqual(apk.main(args), 2)

    def test_archive_user_warning_blocks_without_echoing_member_names(self):
        self.artifact()
        def warn_instead_of_open(*args, **kwargs):
            warnings.warn('Overlapped entries: private-member-name', UserWarning)
            raise AssertionError('warning must abort before continuing')
        stderr = io.StringIO()
        with patch.object(apk.zipfile.ZipFile, 'open', warn_instead_of_open), redirect_stderr(stderr):
            report = apk.inspect(self.path)
        self.assertEqual(report['counts']['BLOCKED'], 3)
        self.assertIsNone(report['artifact_sha256'])
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn('private-member-name', json.dumps(report))

    def test_aggregate_state_tracks_checks_and_incomplete_defaults(self):
        for states, expected in [(['PASS'], 'PASS'), (['PASS', 'FAIL'], 'FAIL'),
                                 (['FAIL', 'BLOCKED'], 'BLOCKED'), ([], 'BLOCKED'),
                                 (['NOT_RUN'], 'BLOCKED'), (['DEFERRED'], 'BLOCKED')]:
            with self.subTest(states=states):
                state, counts = apk.summarize([{'state': value} for value in states])
                self.assertEqual(state, expected)
                self.assertEqual(counts['FAIL'], states.count('FAIL'))

    def test_seeded_archive_mutations_are_bounded_and_never_crash(self):
        self.artifact()
        original = self.path.read_bytes()
        rng = random.Random(20261112)
        for trial in range(300):
            data = bytearray(original)
            at = rng.randrange(len(data))
            operation = trial % 6
            if operation == 0:
                data[at] ^= rng.randrange(1, 256)
            elif operation == 1:
                del data[at:]
            elif operation == 2:
                data[at:at] = b'\0' * rng.randrange(1, 128)
            elif operation == 3:
                del data[at:at + rng.randrange(1, 128)]
            elif operation == 4:
                data[at:at] = data[max(0, at-50):at]
            else:
                data[at:at] = b'\xff' * 50000
            self.path.write_bytes(data)
            result = apk.inspect(self.path)
            self.assertEqual(result['state'], 'BLOCKED')
            self.assertEqual(sum(result['counts'].values()), 3)


if __name__ == '__main__':
    unittest.main()
