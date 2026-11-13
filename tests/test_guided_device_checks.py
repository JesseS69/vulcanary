from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from vulcanary import candidate_tests, guided_device_checks as guided
from test_candidate_tests import example


class GuidedDeviceChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'manifest.json'
        self.spec = example()
        self.spec['candidate']['platform'] = 'android'

    def register(self):
        doc = {'schema': 'vulcanary.candidate-manifest.v1',
               'manifest_sha256': candidate_tests.digest(self.spec), 'spec': self.spec}
        self.path.write_text(json.dumps(doc))
        return doc

    def test_preparation_is_not_execution_or_evidence(self):
        self.register()
        report = guided.prepare(self.path)
        self.assertEqual(report['state'], 'NOT_RUN')
        self.assertEqual(len(report['checks']), 6)
        self.assertEqual(report['evidence'], [])
        self.assertFalse(report['executed'])
        self.assertEqual(report['counts']['PASS'], 0)
        self.assertEqual(report['counts']['NOT_RUN'], 6)
        self.assertEqual(report['policy_effect'], 'none')
        self.assertFalse(report['independent_certification'])
        for row in report['checks']:
            self.assertFalse(row['executed'])
            self.assertIsNone(row['observed'])
            self.assertEqual(row['state'], 'NOT_RUN')
        self.assertIn('artifact_sha256', report['missing_identity_fields'])
        self.assertIn('privacy-device-logs', report['unsupported_requirements'])

    def test_only_requested_checks_and_no_vacuous_pass(self):
        for requirements, count in [(['password-controls'], 2), (['database-authorization'], 0)]:
            self.spec['requirements'] = requirements
            self.register()
            report = guided.prepare(self.path)
            self.assertEqual(len(report['checks']), count)
            self.assertEqual(report['state'], 'NOT_RUN')

    def test_changed_manifest_refused_and_new_identity_distinct(self):
        doc = self.register()
        before = guided.prepare(self.path)
        self.spec['candidate']['artifact_sha256'] = 'c'*64
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            guided.prepare(self.path)
        self.register()
        after = guided.prepare(self.path)
        self.assertNotEqual(before['candidate_sha256'], after['candidate_sha256'])
        self.assertNotEqual(before['manifest_sha256'], after['manifest_sha256'])
        self.assertEqual(before['checklist_sha256'], after['checklist_sha256'])

    def test_ios_supported_other_platforms_refused(self):
        self.spec['candidate']['platform'] = 'ios'
        self.register()
        self.assertEqual(guided.prepare(self.path)['platform'], 'ios')
        for platform in ('web', 'synthetic-model'):
            self.spec['candidate']['platform'] = platform
            self.register()
            with self.assertRaises(ValueError):
                guided.prepare(self.path)

    def test_private_identifiers_not_copied_and_checksums_match(self):
        marker = 'PRIVATE_VERSION_MARKER'
        self.spec['candidate']['installed_version'] = marker
        self.register()
        output = self.root / 'export'
        guided.export(guided.prepare(self.path), output)
        for path in output.iterdir():
            self.assertNotIn(marker, path.read_text())
            self.assertNotIn(str(self.root), path.read_text())
        sums = json.loads((output / 'checksums.json').read_text())
        for name, expected in sums.items():
            self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), expected)
        with self.assertRaises(FileExistsError):
            guided.export(guided.prepare(self.path), output)

    def test_cli_returns_two_even_after_successful_preparation(self):
        self.register()
        for source, target, state in [(self.path, self.root / 'good', 'NOT_RUN'),
                                       (self.root / 'PRIVATE_MISSING', self.root / 'bad', 'BLOCKED'),
                                       (self.path, self.root / 'good', 'BLOCKED')]:
            stream = io.StringIO()
            with redirect_stdout(stream):
                code = guided.main(['--manifest', str(source), '--output', str(target)])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stream.getvalue())['state'], state)
            self.assertNotIn('PRIVATE_MISSING', stream.getvalue())

    def test_unsafe_scope_refused(self):
        for key, value in [('environment', 'production'), ('synthetic_data', False)]:
            self.spec = example()
            self.spec['candidate']['platform'] = 'android'
            self.spec['scope'][key] = value
            self.register()
            with self.assertRaises(ValueError):
                guided.prepare(self.path)


if __name__ == '__main__':
    unittest.main()
