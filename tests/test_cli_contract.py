"""Public CLI contract; all mutations and failure injections use temporary state."""
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import cli
from vulcanary.cli_errors import ERRORS, JSON_ERRORS, fail
from vulcanary.adapters import AdapterError


def invoke(arguments):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        try:
            code = cli.main(arguments)
        except SystemExit as error:
            code = error.code
    return code, output.getvalue(), errors.getvalue()


class CLIContractTests(unittest.TestCase):
    def test_command_option_snapshot(self):
        expected = {
            "scan": "path --config --json --sarif --sbom --spdx --openvex --ruleset-manifest --provenance --baseline-json --github-annotations --github-summary --no-fail --offline --semgrep-json --gitleaks-json --trivy-json --checkov-json --zap-json --prowler-json --sarif-json --trivy-image-json",
            "dashboard": "--repository,-r --host --port --no-open --monitor-interval --history-secrets --gitleaks-executable",
            "setup": "--repository,-r --monitor-interval --port --history-secrets --gitleaks-executable",
            "start": "--no-open", "status": "", "stop": "",
            "config-export": "path", "config-import": "path",
            "dependency-review": "path --base --json --github-annotations --no-fail",
            "web-audit": "url --authorize-target --allow-private-target --json --no-fail",
            "dataflow-prototype": "path --max-depth --max-modules --max-calls --timeout-seconds --json --benchmark-expected",
            "update-check": "",
        }
        parsers = {"scan": cli.scan_parser(), "dashboard": cli.dashboard_parser(),
                   "setup": cli.setup_parser(), "dependency-review": cli.dependency_review_parser(),
                   "web-audit": cli.web_audit_parser(), "dataflow-prototype": cli.dataflow_parser(),
                   "update-check": cli.update_parser()}
        parsers.update({name: cli.service_parser(name) for name in ("start", "stop", "status")})
        parsers.update({name: cli.config_transfer_parser(name) for name in ("config-export", "config-import")})
        self.assertEqual(set(parsers), set(expected))
        for name, parser in parsers.items():
            with self.subTest(command=name):
                self.assertEqual(" ".join(",".join(a.option_strings) if a.option_strings else a.dest
                                          for a in parser._actions if a.dest != "help"), expected[name])
                for prefix in ([], ["--errors-json"]):
                    code, stdout, stderr = invoke(prefix + ([] if name == "scan" else [name]) + ["--help"])
                    self.assertEqual(code, 0)
                    self.assertIn("usage:", stdout)
                    self.assertEqual(stderr, "")
        dataflow = vars(parsers["dataflow-prototype"].parse_args([]))
        self.assertEqual((dataflow["max_depth"], dataflow["max_modules"], dataflow["max_calls"], dataflow["timeout_seconds"]), (3, 10000, 1000000, 120.0))
        self.assertEqual(parsers["setup"].parse_args([]).monitor_interval, 300)
        self.assertEqual(parsers["dashboard"].parse_args([]).host, "127.0.0.1")

    def test_argument_errors_do_not_echo_values_and_context_does_not_leak(self):
        sentinel = "SYNTHETIC_PRIVATE_SENTINEL"
        for arguments in (["--unknown", sentinel], ["dashboard", "--port", sentinel],
                          ["web-audit", sentinel], ["dataflow-prototype", "--max-depth", "99"],
                          ["config-import"], ["dependency-review"], ["status", sentinel]):
            code, stdout, stderr = invoke(["--errors-json", *arguments])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(stderr)["code"], "invalid_arguments")
            self.assertNotIn(sentinel, stdout + stderr)
        self.assertFalse(JSON_ERRORS.get())
        self.assertTrue(invoke(["--unknown"])[2].startswith("error [invalid_arguments]"))

    def test_error_envelope_and_code_vocabulary(self):
        self.assertEqual(set(ERRORS), {"invalid_arguments", "repository_unavailable", "configuration_invalid",
            "report_import_failed", "dataflow_failed", "config_transfer_failed", "web_audit_failed",
            "dependency_review_failed", "service_failed", "update_check_failed", "stale_openvex",
            "baseline_invalid", "summary_destination_missing", "operation_failed"})
        token = JSON_ERRORS.set(True)
        try:
            for code in ERRORS:
                output = io.StringIO()
                with redirect_stderr(output):
                    self.assertEqual(fail(code), 2)
                record = json.loads(output.getvalue())
                self.assertEqual(set(record), {"schema", "code", "message", "action", "exit_code"})
                self.assertEqual(record["schema"], "vulcanary.cli-error.v1")
                self.assertEqual(record["code"], code)
                self.assertTrue(record["message"] and record["action"])
        finally:
            JSON_ERRORS.reset(token)

    def test_scan_exit_codes_and_no_fail_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(invoke([str(root), "--offline"])[0], 0)
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            self.assertEqual(invoke([str(root), "--offline"])[0], 1)
            self.assertEqual(invoke([str(root), "--offline", "--no-fail"])[0], 0)
            self.assertEqual(invoke(["--errors-json", str(root / "absent"), "--no-fail"])[0], 2)
            with patch.object(cli, "scan_dependencies", return_value=([], "OSV unavailable")):
                (root / "app.py").unlink()
                result = invoke([str(root)])
            self.assertEqual(result[0], 0)
            self.assertIn("advisory_lookup_unavailable", result[2])

    def test_operational_errors_are_source_free_in_both_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            for prefix in ([], ["--errors-json"]):
                for target, arguments, code in (
                    ("vulcanary.cli.Config.load", [directory, "--offline"], "configuration_invalid"),
                    ("vulcanary.cli.write_json", [directory, "--offline", "--json", str(Path(directory) / "out.json")], "operation_failed"),
                    ("vulcanary.local_app.load_app_config", ["status"], "service_failed"),
                    ("vulcanary.updates.check_for_update", ["update-check"], "update_check_failed"),
                    ("vulcanary.local_app.export_app_config", ["config-export", str(Path(directory) / "backup.json")], "config_transfer_failed"),
                    ("vulcanary.webaudit.audit_web_target", ["web-audit", "https://example.com", "--authorize-target", "example.com"], "web_audit_failed"),
                    ("vulcanary.dataflow.analyze_python_dataflow", ["dataflow-prototype", directory], "dataflow_failed"),
                ):
                    with self.subTest(target=target, prefix=prefix), patch(target, side_effect=OSError("SYNTHETIC_PRIVATE_SENTINEL")):
                        status, output, errors = invoke(prefix + arguments)
                    self.assertEqual(status, 2)
                    self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", output + errors)
                    if prefix:
                        self.assertEqual(json.loads(errors)["code"], code)
                    else:
                        self.assertIn(f"error [{code}]", errors)

    def test_service_and_update_status_codes_remain_command_specific(self):
        with patch("vulcanary.local_app.load_app_config", return_value={}), patch("vulcanary.local_app.service_status", return_value={"running": False, "repositories": 0}):
            self.assertEqual(invoke(["status"])[0], 1)
        with patch("vulcanary.updates.check_for_update", return_value={"current": "0", "latest": "1", "update_available": True, "url": "https://example.com"}):
            self.assertEqual(invoke(["update-check"])[0], 1)

    def test_remaining_error_routes_and_stale_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vex = root / "old.vex"
            vex.write_text("preserve", encoding="utf-8")
            cases = [
                ([str(root / "absent")], "repository_unavailable"),
                ([str(root), "--offline", "--openvex", str(vex)], "stale_openvex"),
                ([str(root), "--offline", "--baseline-json", str(root / "absent")], "baseline_invalid"),
                ([str(root), "--offline", "--github-summary"], "summary_destination_missing"),
            ]
            with patch.dict("os.environ", {}, clear=True):
                for arguments, expected in cases:
                    code, _, errors = invoke(["--errors-json", *arguments])
                    self.assertEqual(code, 2)
                    self.assertEqual(json.loads(errors.splitlines()[-1])["code"], expected)
            self.assertEqual(vex.read_text(), "preserve")
            with patch.object(cli, "import_report", side_effect=AdapterError("SYNTHETIC_PRIVATE_SENTINEL")):
                code, output, errors = invoke(["--errors-json", directory, "--offline", "--sarif-json", "unused"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(errors)["code"], "report_import_failed")
            self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", output + errors)
            with patch("vulcanary.admission.review_dependency_changes", side_effect=ValueError("SYNTHETIC_PRIVATE_SENTINEL")):
                code, output, errors = invoke(["--errors-json", "dependency-review", directory, "--base", directory])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(errors)["code"], "dependency_review_failed")
            self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", output + errors)

    def test_prefix_does_not_consume_an_option_value_or_hide_programming_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cli.Config, "load", side_effect=ValueError("private")) as load:
                self.assertEqual(invoke([directory, "--config=--errors-json"])[0], 2)
                self.assertEqual(load.call_args.args[1], Path("--errors-json"))
            with patch.object(cli, "scan", side_effect=AssertionError("programming defect")):
                with self.assertRaises(AssertionError), redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                    cli.main(["--errors-json", directory, "--offline"])
            self.assertFalse(JSON_ERRORS.get())

    def test_versioned_errors_do_not_replace_reports_or_gate_experimental_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("eval(request.args.get('q'))\n", encoding="utf-8")
            code, stdout, stderr = invoke(["--errors-json", "dataflow-prototype", directory])
            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertEqual(json.loads(stdout)["policy_effect"], "none")
