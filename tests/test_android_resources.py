import hashlib
import io
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch
import zipfile

from vulcanary import _android_manifest as axml
from vulcanary import _android_resources as resources
from vulcanary import apk_inspection as apk
from test_apk_inspection import binary_manifest

REFERENCE = 0x7f010000


def pool(values):
    payload, offsets = b'', []
    for value in values:
        raw = value.encode('utf-8')
        offsets.append(len(payload))
        payload += bytes([len(value), len(raw)]) + raw + b'\0'
    payload += b'\0' * (-len(payload) % 4)
    return (struct.pack('<HHI5I', 1, 28, 28 + 4*len(values) + len(payload), len(values), 0, 0x100,
                        28+4*len(values), 0) + struct.pack('<'+'I'*len(values), *offsets) + payload)


def table(path='res/xml/private-backup.xml', *, other_path=None, alias=False, sparse=False, default=True):
    values = [path] + ([other_path] if other_path is not None else [])
    global_pool = pool(values)
    types, keys = pool(['xml']), pool(['private_key_name'])
    def variant(index, qualified):
        config = bytearray(struct.pack('<I', 28) + b'\0'*24)
        if qualified:
            config[24] = 31
        return (struct.pack('<HHIBBHII', 0x201, 48, 68, 1, int(sparse), 0, 1, 52)
                + config + struct.pack('<IHHIHBBI', 0, 8, 2, 0, 8, 0, 1 if alias else 3, index))
    spec = struct.pack('<HHIBBHII', 0x202, 16, 20, 1, 0, 0, 1, 0)
    children = types + keys + spec + variant(0, not default)
    if other_path is not None:
        children += variant(1, True)
    package = bytearray(288)
    struct.pack_into('<HHII', package, 0, 0x200, 288, 288+len(children), 0x7f)
    struct.pack_into('<5I', package, 268, 288, 1, 288+len(types), 1, 0)
    body = global_pool + package + children
    return struct.pack('<HHII', 2, 12, 12+len(body), 1) + body


class AndroidResourceTests(unittest.TestCase):
    def test_direct_and_identical_configuration_links(self):
        self.assertEqual(resources.resolve_xml(table(), REFERENCE), 'res/xml/private-backup.xml')
        self.assertEqual(resources.resolve_xml(table(other_path='res/xml/private-backup.xml'), REFERENCE),
                         'res/xml/private-backup.xml')

    def test_ambiguous_alias_sparse_missing_default_and_traversal_refused(self):
        for data in (table(other_path='res/xml/other.xml'), table(alias=True), table(sparse=True),
                     table(default=False), table(path='res/../private.xml')):
            with self.subTest(data_hash=hashlib.sha256(data).hexdigest()):
                with self.assertRaises(axml.ManifestError):
                    resources.resolve_xml(data, REFERENCE)
        with self.assertRaises(axml.ManifestError):
            resources.resolve_xml(table(), 0x01010000)

    def test_backup_manifest_attributes_preserve_existing_boolean_api(self):
        data = binary_manifest({'debuggable': False, 'fullBackupContent': None, 'dataExtractionRules': None})
        data = data.replace(struct.pack('<I', 0x7f000001), struct.pack('<I', REFERENCE))
        self.assertEqual(axml.parse(data), {'debuggable': False})
        extended = axml.parse(data, include_backup=True)
        self.assertEqual(extended['fullBackupContent'], {'kind': 'reference', 'value': REFERENCE})
        self.assertEqual(extended['dataExtractionRules'], {'kind': 'reference', 'value': REFERENCE})
        with self.assertRaises(axml.ManifestError):
            axml.parse(binary_manifest({'fullBackupContent': None}, wrong_id=True), include_backup=True)

    def test_invalid_spec_and_resource_bounds_refused(self):
        original = table()
        spec = original.index(struct.pack('<HHI', 0x202, 16, 20))
        for offset, value in ((spec + 8, 2), (spec + 12, 0), (spec + 12, 65537)):
            data = bytearray(original)
            struct.pack_into('<I', data, offset, value)
            with self.assertRaises(axml.ManifestError):
                resources.resolve_xml(bytes(data), REFERENCE)
        with patch.object(resources, 'MAX_TABLE', len(original) - 1):
            with self.assertRaises(axml.ManifestError):
                resources.resolve_xml(original, REFERENCE)

    def test_missing_or_oversize_linked_member_stays_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'candidate.apk'
            manifest = binary_manifest({'fullBackupContent': None})
            manifest = manifest.replace(struct.pack('<I', 0x7f000001), struct.pack('<I', REFERENCE))
            for content in (None, b'x' * (axml.MAX_XML + 1)):
                with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr('AndroidManifest.xml', manifest)
                    archive.writestr('resources.arsc', table())
                    if content is not None:
                        archive.writestr('res/xml/private-backup.xml', content)
                report = apk.inspect(path)
                self.assertEqual(report['backup_resources'][0]['resolution'], 'unresolved')
                self.assertIsNone(report['backup_resources'][0]['member_sha256'])
                self.assertEqual(report['state'], 'BLOCKED')

    def test_link_evidence_does_not_pass_exclusions_or_export_private_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'candidate.apk'
            manifest = binary_manifest({'debuggable': False, 'allowBackup': False, 'fullBackupContent': None})
            manifest = manifest.replace(struct.pack('<I', 0x7f000001), struct.pack('<I', REFERENCE))
            rule_bytes = b'rule bytes require separate validation'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('AndroidManifest.xml', manifest)
                archive.writestr('resources.arsc', table())
                archive.writestr('res/xml/private-backup.xml', rule_bytes)
            report = apk.inspect(path)
            self.assertEqual(report['counts'], {'PASS': 2, 'FAIL': 0, 'BLOCKED': 1})
            self.assertEqual(report['backup_resources'][0]['resolution'], 'resolved_file')
            self.assertEqual(report['backup_resources'][0]['member_sha256'], hashlib.sha256(rule_bytes).hexdigest())
            apk.export(report, Path(directory)/'review')
            for output in (Path(directory)/'review').iterdir():
                for private in ('private-backup', 'private_key_name', directory, rule_bytes.decode()):
                    self.assertNotIn(private, output.read_text())

    def test_unresolved_and_literal_forms_never_claim_rule_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'candidate.apk'
            for value, expected in ((None, 'unresolved'), (False, 'literal_false'), (True, 'literal_true')):
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr('AndroidManifest.xml', binary_manifest({'fullBackupContent': value}))
                report = apk.inspect(path)
                self.assertEqual(report['backup_resources'][0]['resolution'], expected)
                self.assertEqual(report['checks'][2]['state'], 'BLOCKED')

    def test_resource_warning_discards_identity_and_all_declarations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'candidate.apk'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('AndroidManifest.xml', binary_manifest({'fullBackupContent': None}))
                archive.writestr('resources.arsc', table())
            original = apk.read_member
            def warned(archive, name, limit):
                if name == 'resources.arsc':
                    raise UserWarning('private-resource-name')
                return original(archive, name, limit)
            stderr = io.StringIO()
            with patch.object(apk, 'read_member', warned), redirect_stderr(stderr):
                report = apk.inspect(path)
            self.assertIsNone(report['artifact_sha256'])
            self.assertEqual(report['counts']['BLOCKED'], 3)
            self.assertNotIn('private-resource-name', json.dumps(report))
            self.assertEqual(stderr.getvalue(), '')

    def test_seeded_table_mutations_are_bounded(self):
        rng, original = random.Random(20261113), table()
        for trial in range(1000):
            data = bytearray(original)
            at = rng.randrange(len(data))
            if trial % 2:
                data[at] ^= rng.randrange(1, 256)
            else:
                del data[at:]
            try:
                result = resources.resolve_xml(bytes(data), REFERENCE)
                self.assertTrue(result.startswith('res/') and result.endswith('.xml'))
            except (axml.ManifestError, UnicodeDecodeError):
                pass


if __name__ == '__main__':
    unittest.main()
