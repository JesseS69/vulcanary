import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import candidate_tests as candidate
from vulcanary import transfer_model


def example():
    return {'candidate': {'platform': 'synthetic-model', 'source_commit': None,
            'artifact_sha256': None, 'installed_version': None, 'os_version': None,
            'device_sha256': None, 'environment_sha256': 'a'*64,
            'account_roles': [{'role': 'source', 'identity_sha256': 'b'*64},
                              {'role': 'receiver', 'identity_sha256': 'c'*64}],
            'transfer_eligibility': 'unknown'},
            'scope': {'environment': 'local-synthetic', 'synthetic_data': True,
                      'permitted_actions': ['register', 'run-bundled-transfer-model']},
            'requirements': list(candidate.REQUIREMENTS)}


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = self.root / 'spec.json'
        self.manifest = self.root / 'registered.json'

    def register(self, spec=None):
        self.spec.write_text(json.dumps(spec or example()), encoding='utf-8')
        return candidate.register(self.spec, self.manifest)

    def test_manifest_identity_covers_every_candidate_dimension(self):
        spec = example()
        base = candidate.digest(spec)
        for field, value in {'platform': 'android', 'source_commit': 'd'*40,
                             'artifact_sha256': 'd'*64, 'installed_version': '1.2.3',
                             'os_version': 'Android-15', 'device_sha256': 'e'*64,
                             'environment_sha256': 'f'*64, 'transfer_eligibility': 'enabled',
                             'account_roles': [{'role': 'outsider', 'identity_sha256': 'd'*64}]}.items():
            changed = copy.deepcopy(spec)
            changed['candidate'][field] = value
            candidate.validate(changed)
            self.assertNotEqual(candidate.digest(changed), base)

    def test_changed_registered_candidate_is_refused(self):
        doc = self.register()
        doc['spec']['candidate']['platform'] = 'android'
        self.manifest.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            candidate.load(self.manifest)

    def test_scope_never_accepts_live_actions_credentials_or_production(self):
        variants = []
        for key, value in [('environment', 'production'), ('synthetic_data', False),
                           ('permitted_actions', ['register', 'deploy'])]:
            spec = example()
            spec['scope'][key] = value
            variants.append(spec)
        for key in ('password', 'endpoint', 'command'):
            spec = example()
            spec['candidate'][key] = 'secret'
            variants.append(spec)
        for spec in variants:
            with self.assertRaises(ValueError):
                candidate.validate(spec)

    def test_wrong_candidate_and_wrong_method_cannot_pass(self):
        requirement = 'native-termination-restart'
        def record(method='mock', identity='a'*64, state='PASS'):
            return {'requirement': requirement, 'manifest_sha256': identity, 'method': method, 'state': state}
        self.assertEqual(candidate.assess(requirement, 'a'*64, [record()]), 'NOT_RUN')
        self.assertEqual(candidate.assess(requirement, 'a'*64, [record('installed_device', 'b'*64)]), 'NOT_RUN')
        self.assertEqual(candidate.assess(requirement, 'a'*64, [record('user_report')]), 'NOT_RUN')
        self.assertEqual(candidate.assess(requirement, 'a'*64, [record('installed_device')]), 'PASS')
        self.assertEqual(candidate.assess(requirement, 'a'*64, [record('installed_device', state='FAIL'), record('installed_device')]), 'FAIL')

    def test_all_required_methods_must_exist_not_just_one(self):
        requirement = 'privacy-app-switcher'
        records = [{'requirement': requirement, 'manifest_sha256': 'a'*64, 'method': 'installed_device', 'state': 'PASS'}]
        self.assertEqual(candidate.assess(requirement, 'a'*64, records), 'NOT_RUN')
        records.append(records[0] | {'method': 'human_observation'})
        self.assertEqual(candidate.assess(requirement, 'a'*64, records), 'PASS')

    def test_reference_model_does_not_pass_application_requirements(self):
        self.register()
        report = candidate.execute(self.manifest, authorized=True)
        self.assertEqual(report['counts']['PASS'], 1)
        self.assertEqual(report['counts']['BLOCKED'], len(candidate.REQUIREMENTS)-1)
        self.assertTrue(all(r['state'] == 'PASS' for r in report['synthetic_scenarios']))
        self.assertEqual(report['state'], 'BLOCKED')
        self.assertEqual(report['policy_effect'], 'none')
        self.assertFalse(report['independent_certification'])

    def test_android_candidate_cannot_inherit_model_pass(self):
        spec = example()
        spec['candidate']['platform'] = 'android'
        self.register(spec)
        report = candidate.execute(self.manifest, authorized=True)
        self.assertEqual(report['counts']['PASS'], 0)
        self.assertEqual(report['evidence'], [])

    def test_no_authorization_no_model_execution(self):
        self.register()
        with patch.object(candidate, 'run_scenarios', side_effect=AssertionError('must not execute')):
            report = candidate.execute(self.manifest)
        self.assertEqual(report['counts']['PASS'], 0)
        self.assertEqual(report['synthetic_scenarios'], [])

    def test_empty_results_never_pass(self):
        self.register()
        with patch.object(candidate, 'run_scenarios', return_value=[]):
            report = candidate.execute(self.manifest, authorized=True)
        self.assertEqual(report['counts']['PASS'], 0)

    def test_export_contains_no_synthetic_key_canary_or_private_paths(self):
        self.register()
        marker = b'synthetic-secret-never-export-1234'
        with patch.object(transfer_model.secrets, 'token_bytes', return_value=marker):
            report = candidate.execute(self.manifest, authorized=True)
        candidate.export(report, self.root / 'review')
        for path in (self.root / 'review').iterdir():
            raw = path.read_bytes()
            for forbidden in (marker, marker.hex().encode(), str(self.root).encode(), b'receiver-account-password'):
                self.assertNotIn(forbidden, raw)
        with self.assertRaises(FileExistsError):
            candidate.export(report, self.root / 'review')

    def test_models_retain_interruption_and_uncertain_events_after_retry(self):
        results = {r['scenario']: r for r in transfer_model.run_scenarios()}
        events = results['partial_install']['events']
        self.assertIn({'operation': 'install', 'outcome': 'interrupted'}, events)
        self.assertIn({'operation': 'install', 'outcome': 'installed'}, events)
        self.assertIn({'operation': 'complete', 'outcome': 'uncertain'}, results['lost_completion_response']['events'])

    def test_deliberately_broken_models_fail_the_relevant_assertions(self):
        controls = {'allow_unapproved': 'refusal', 'ignore_account': 'account_switch',
                    'non_atomic': 'partial_install', 'duplicate_install': 'duplicate_install',
                    'reexport': 'lost_upload_response', 'corrupt_source': 'source_preserved'}
        for defect, scenario in controls.items():
            results = {r['scenario']: r for r in transfer_model.run_scenarios(defect=defect)}
            self.assertEqual(results[scenario]['state'], 'FAIL', defect)

    def test_cli_end_to_end_and_output_refusal(self):
        self.spec.write_text(json.dumps(example()))
        self.assertEqual(candidate.main(['register', '--spec', str(self.spec), '--output', str(self.manifest)]), 0)
        args = ['run', '--manifest', str(self.manifest), '--output', str(self.root/'report'), '--authorize-bundled-model']
        self.assertEqual(candidate.main(args), 2)  # Model PASS does not hide missing app coverage.
        with patch.object(candidate, 'execute', side_effect=AssertionError('must not execute')):
            self.assertEqual(candidate.main(args), 2)


if __name__ == '__main__':
    unittest.main()
