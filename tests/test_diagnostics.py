import unittest
import io
import json
import tempfile
from subprocess import CompletedProcess
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from vulcanary.diagnostics import dependency_diagnostics, dataflow_diagnostics
from vulcanary.cli import main
from vulcanary.dashboard import DashboardState
from vulcanary.dataflow import analyze_python_dataflow
from vulcanary.history_secrets import HistoryScanError
from vulcanary import evaluator


class DiagnosticTests(unittest.TestCase):
    def test_evaluation_dependency_warning_has_guidance_without_executing_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            def fake_run(command, cwd, *args, **kwargs):
                if command[:3] == ['git', 'worktree', 'add']:
                    (Path(command[4]) / 'package.json').write_text('{}', encoding='utf-8')
                return CompletedProcess(command, 0, str(root) if '--show-toplevel' in command else '', '')
            candidate = {'parent': 'parent', 'package': 'dep', 'candidate_version': '2.0', 'advisories': ['demo']}
            with patch.object(evaluator, '_run', side_effect=fake_run), patch.object(evaluator, 'scoped_override_candidates', return_value=[candidate]), patch.object(evaluator, 'run_verification', return_value={'passed': True, 'skipped': True}):
                result = evaluator.evaluate_scoped_overrides([], str(root), dependency_scanner=lambda _: ([], 'OSV unavailable'))
            warning = result['results'][0]['warnings'][0]
            self.assertEqual(warning['code'], 'advisory_lookup_unavailable')
            self.assertTrue(warning['action'])

    def test_vex_skip_is_recorded_before_normalized_export_even_with_stale_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for stale in (False, True):
                vex, output = root / 'output.vex', root / 'report.json'
                if stale:
                    vex.write_text('old output', encoding='utf-8')
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    result = main([str(root), '--offline', '--json', str(output), '--openvex', str(vex)])
                self.assertEqual(result, 2 if stale else 0)
                warning = json.loads(output.read_text(encoding='utf-8'))['policy']['warnings'][0]
                self.assertEqual(warning['code'], 'openvex_no_statements')
                self.assertTrue(warning['action'])
                if stale:
                    self.assertEqual(vex.read_text(), 'old output')
                else:
                    self.assertFalse(vex.exists())

    def test_history_error_does_not_echo_tool_exception_or_erase_exposures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = DashboardState()
            state.history_secrets_enabled = True
            state.gitleaks_executable = root / 'tool.exe'
            key = str(root.resolve())
            state.history_exposures[key] = {'retained': {'fingerprint': 'retained'}}
            with patch('vulcanary.dashboard.scan_history', side_effect=HistoryScanError('SYNTHETIC_PRIVATE_SENTINEL')):
                with self.assertRaises(HistoryScanError) as error:
                    state.scan_repository_history(root)
            self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', str(error.exception))
            self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', json.dumps(state.snapshot()))
            warning = state.history_scan_status[key]['warnings'][0]
            self.assertEqual(warning['code'], 'history_scan_failed')
            self.assertEqual(warning['path'], key)
            self.assertIn('retained', state.history_exposures[key])

    def test_dataflow_guidance_is_additive_and_parser_details_are_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.py').write_text('eval(unknown())\n', encoding='utf-8')
            (root / 'broken.py').write_text('SYNTHETIC_PRIVATE_SENTINEL = (\n', encoding='utf-8')
            report = analyze_python_dataflow(root)
            self.assertTrue(report['unmodeled_constructs'])
            self.assertEqual(report['parse_errors'], 1)
            self.assertNotIn('SYNTHETIC_PRIVATE_SENTINEL', json.dumps(report))
            self.assertEqual(report['policy_effect'], 'none')
            self.assertTrue(all(item['action'] and 'path' in item for item in report['warnings']))
            stripped = {key: value for key, value in report.items() if key != 'warnings'}
            with patch('vulcanary.diagnostics.dataflow_diagnostics', return_value=[]):
                baseline = analyze_python_dataflow(root)
            self.assertEqual(stripped, baseline)
            limits = {'unmodeled_constructs': [], 'analysis_truncations': [], 'analysis_limits': [{'category': key} for key in ('module_limit','call_limit','time_limit','source_size_limit')]}
            self.assertEqual(len(dataflow_diagnostics(limits, [])), 4)
    def test_dependency_warning_shapes_are_actionable_and_additive(self):
        records = dependency_diagnostics([
            "Cargo.lock: dependency input is 35651584 bytes and exceeds the 33554432-byte limit",
            "Gemfile.lock: invalid Bundler dependency input",
            "requirements.txt:requests", "pom.xml: missing resolved dependency tree",
        ], "OSV lookup unavailable")
        self.assertEqual(len(records), 5)
        self.assertEqual(records[0]["code"], "dependency_input_too_large")
        self.assertIn("34.0 MiB", records[0]["message"])
        self.assertEqual(records[0]["limit_bytes"], 33554432)
        self.assertEqual(records[1]["path"], "Gemfile.lock")
        self.assertEqual(records[2]["code"], "dependency_version_unresolved")
        self.assertEqual(records[-1]["code"], "advisory_lookup_unavailable")
        self.assertTrue(all(item["message"] and item["action"] and item["capability"] for item in records))
        self.assertEqual(dependency_diagnostics([]), [])
