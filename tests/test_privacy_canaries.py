import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from urllib.parse import quote

from vulcanary import privacy_canaries as privacy


class PrivacyCanaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.canary = self.root/'private.json'
        privacy.create(self.canary)
        self.marker = privacy.load(self.canary)['marker']
        self.log = self.root/'synthetic.log'

    def scan(self, paths=None):
        return privacy.scan(self.canary, paths or [self.log], 'device-log', 'a'*64, authorized=True)

    def test_exact_literal_and_encoded_markers_are_detected_without_leakage(self):
        raw = self.marker.encode()
        forms = [raw, raw.hex().encode(), base64.b64encode(raw), quote(self.marker, safe='').encode()]
        self.log.write_bytes(b'\n'.join(forms))
        result = self.scan()
        self.assertEqual(result['state'], 'FAIL')
        self.assertEqual(len(result['files'][0]['matches']), 4)
        privacy.export(result, self.root/'report')
        for path in (self.root/'report').iterdir():
            content = path.read_bytes()
            for secret in forms + [str(self.root).encode()]:
                self.assertNotIn(secret, content)

    def test_other_canary_and_generic_marker_do_not_count_as_exact_secret(self):
        other = self.root/'other.json'
        privacy.create(other)
        self.log.write_text(privacy.load(other)['marker'] + '\nVULCANARY_TEST/generic')
        result = self.scan()
        self.assertEqual(result['state'], 'PASS')
        self.assertEqual(result['files'][0]['matches'], [])

    def test_missing_oversize_and_mixed_inputs_keep_incomplete_coverage(self):
        self.log.write_text('clean')
        result = self.scan([self.log, self.root/'missing'])
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertFalse(result['coverage_complete'])
        with patch.object(privacy, 'MAX_BYTES', 3):
            self.assertEqual(self.scan()['state'], 'BLOCKED')
        self.log.write_text(self.marker)
        result = self.scan([self.log, self.root/'missing'])
        self.assertEqual(result['state'], 'FAIL')
        self.assertEqual(result['counts']['BLOCKED'], 1)
        self.assertFalse(result['coverage_complete'])

    def test_match_limit_is_visible_and_never_clean(self):
        self.log.write_text(self.marker * 101)
        result = self.scan()
        self.assertEqual(result['state'], 'FAIL')
        self.assertEqual(len(result['files'][0]['matches']), 100)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['files'][0]['reason'], 'match_limit')

    def test_authorization_and_input_count_before_any_read(self):
        with patch.object(privacy, 'load', side_effect=AssertionError('must not read')):
            with self.assertRaises(ValueError):
                privacy.scan(self.canary, [self.log], 'device-log', 'a'*64)
            with self.assertRaises(ValueError):
                privacy.scan(self.canary, [self.log]*17, 'device-log', 'a'*64, authorized=True)

    def test_real_secret_shape_and_changed_registry_are_refused(self):
        record = json.loads(self.canary.read_text())
        record['marker'] = 'real-looking-password'
        self.canary.write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            privacy.load(self.canary)

    def test_stale_canary_digest_is_refused(self):
        record = json.loads(self.canary.read_text())
        record['marker_sha256'] = '0' * 64
        self.canary.write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            privacy.load(self.canary)

    def test_same_handle_changes_block_but_path_ctime_difference_does_not(self):
        self.log.write_text('clean')
        original = self.log.stat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')
        changed = SimpleNamespace(**{key: getattr(original, key) for key in fields})
        changed.st_mtime_ns += 1
        with patch.object(privacy.os, 'fstat', side_effect=[original, changed]):
            result = self.scan()
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertIsNone(result['files'][0]['sha256'])
        changed.st_mtime_ns = original.st_mtime_ns
        changed.st_ctime_ns += 1
        with patch.object(privacy.os, 'fstat', return_value=changed):
            self.assertEqual(self.scan()['state'], 'PASS')
        with patch.object(privacy.os, 'fstat', side_effect=[original, changed]):
            self.assertEqual(self.scan()['state'], 'BLOCKED')

    def test_cli_and_no_overwrite(self):
        self.log.write_text(self.marker)
        args = ['scan', '--canary', str(self.canary), '--file', str(self.log), '--category', 'browser-log',
                '--manifest-sha256', 'a'*64, '--authorize-synthetic-exports', '--output', str(self.root/'report')]
        self.assertEqual(privacy.main(args), 1)
        with patch.object(privacy, 'scan', side_effect=AssertionError('must not scan')):
            self.assertEqual(privacy.main(args), 2)


if __name__ == '__main__':
    unittest.main()
