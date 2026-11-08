import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import security_testing as testing
from vulcanary.config import Config
from vulcanary.scanners import scan


class SecurityTestingTests(unittest.TestCase):
    def register(self, root, source="eval(user_input)\n", checks=None):
        spec = {"files": [source], "checks": checks or [
            {"method": "automated", "rule": "CODE-PY-EVAL", "expected_count": 0}]}
        path = root / "spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        testing.register(path, root / "target.json", authorized=True)
        return root / "target.json"

    def test_real_adapter_all_states_and_no_target_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self.register(root, "raise RuntimeError('MUST_NOT_EXECUTE')\neval(user_input)\n", [
                {"method": "automated", "rule": "CODE-PY-EVAL", "expected_count": 0},
                {"method": "automated", "rule": "CODE-PY-EVAL", "expected_count": 1},
                {"method": "manual", "kind": "device-privacy"},
                {"method": "deferred", "kind": "crypto-integration"}])
            with patch("socket.socket", side_effect=AssertionError("No network")), patch("subprocess.Popen", side_effect=AssertionError("No processes")):
                report = testing.execute(target)
            self.assertEqual([item["state"] for item in report["checks"]], ["FAIL", "PASS", "NOT_RUN", "DEFERRED"])
            self.assertEqual(report["state"], "FAIL")
            self.assertEqual(report["files_analyzed"], 1)
            self.assertEqual(report["cleanup"], "complete")
            self.assertEqual(report["evidence"], [{"rule": "CODE-PY-EVAL", "file": "source-001.py", "line": 2}])
            self.assertTrue(report["checks"][0]["attempted"])
            self.assertFalse(report["checks"][2]["executed"])

    def test_tampered_snapshot_or_plan_is_blocked_without_running(self):
        for section in ("files", "checks"):
            with tempfile.TemporaryDirectory() as directory:
                target = self.register(Path(directory))
                data = json.loads(target.read_text())
                if section == "files":
                    data["spec"][section][0] = "print('changed')\n"
                else:
                    data["spec"][section][0]["expected_count"] = 1
                target.write_text(json.dumps(data))
                with patch.object(testing, "scan", side_effect=AssertionError("Must not run")):
                    report = testing.execute(target)
                self.assertEqual(report["state"], "BLOCKED")
                self.assertEqual(report["counts"]["PASS"], 0)
                self.assertIsNone(report["target_sha256"])

    def test_production_scope_is_rejected_and_authorization_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self.register(root)
            with self.assertRaises(ValueError):
                testing.register(root / "spec.json", root / "other.json")
            data = json.loads(target.read_text())
            data["scope"]["environment"] = "production"
            target.write_text(json.dumps(data))
            self.assertEqual(testing.execute(target)["state"], "BLOCKED")

    def test_evidence_allowlist_removes_synthetic_secrets_source_and_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = "AKIA" + "Z9" * 8
            target = self.register(root, f"key = '{marker}'\nraise RuntimeError('PRIVATE_DETAIL')\n")
            report = testing.execute(target)
            self.assertTrue(any(item["rule"] == "SECRET-AWS-KEY" for item in report["evidence"]))
            testing.export_package(report, root / "review")
            exported = "".join(path.read_text() for path in (root / "review").iterdir())
            for forbidden in (marker, "PRIVATE_DETAIL", directory, "key ="):
                self.assertNotIn(forbidden, exported)
            self.assertFalse(report["independent_certification"])
            self.assertEqual(report["policy_effect"], "none")
            checksums = json.loads((root / "review/checksums.json").read_text())
            for name, expected in checksums.items():
                self.assertEqual(hashlib.sha256((root / "review" / name).read_bytes()).hexdigest(), expected)

    def test_skipped_read_is_blocked_not_a_clean_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.register(Path(directory))
            with patch("vulcanary.scanners.read_source_text", side_effect=OSError("PRIVATE_DETAIL")):
                report = testing.execute(target)
            self.assertEqual(report["state"], "BLOCKED")
            self.assertTrue(report["checks"][0]["attempted"])
            self.assertFalse(report["checks"][0]["executed"])
            self.assertNotIn("PRIVATE_DETAIL", json.dumps(report))
            self.assertEqual(report["evidence"], [])

    def test_missing_enumeration_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.register(Path(directory))
            with patch("vulcanary.scanners.iter_files", return_value=iter([])):
                self.assertEqual(testing.execute(target)["state"], "BLOCKED")

    def test_adapter_exception_blocks_and_temporary_files_are_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.register(Path(directory))
            staged = []
            def broken(root, config, **kwargs):
                staged.append(root)
                raise RuntimeError("PRIVATE_DETAIL")
            with patch.object(testing, "scan", side_effect=broken):
                report = testing.execute(target)
            self.assertEqual(report["state"], "BLOCKED")
            self.assertFalse(staged[0].exists())
            self.assertNotIn("PRIVATE_DETAIL", json.dumps(report))

    def test_retests_bind_exact_target_and_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.register(Path(directory))
            first, second = testing.execute(target), testing.execute(target)
            self.assertNotEqual(first["run_id"], second["run_id"])
            for key in ("checks", "target_sha256", "plan_sha256", "ruleset_digest", "evidence"):
                self.assertEqual(first[key], second[key])

    def test_manual_only_never_calls_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.register(Path(directory), checks=[{"method": "manual", "kind": "accessibility"}])
            with patch.object(testing, "scan", side_effect=AssertionError("Must not run")):
                report = testing.execute(target)
            self.assertEqual(report["state"], "NOT_RUN")
            self.assertEqual(report["files_analyzed"], 0)

    def test_invalid_and_overlarge_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for invalid in ({"files": ["def broken("], "checks": []},
                            {"files": ["# vulcanary:ignore CODE-PY-EVAL"], "checks": []},
                            {"files": ["pass"], "checks": [{"method": "execute", "command": "bad"}]},
                            {"files": ["pass"], "checks": [{"method": "automated", "rule": "IAC-DOCKER-ROOT", "expected_count": 0}]},
                            {"files": ["pass"], "checks": [], "endpoints": ["https://example.com"]}):
                path = root / "invalid.json"
                path.write_text(json.dumps(invalid))
                with self.assertRaises((ValueError, SyntaxError)):
                    testing.register(path, root / "target.json", authorized=True)
                self.assertFalse((root / "target.json").exists())
            path.write_bytes(b"x" * (testing.MAX_BYTES + 1))
            self.assertEqual(testing.execute(path)["state"], "BLOCKED")

    def test_cli_real_registration_run_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = root / "spec.json"
            spec.write_text(json.dumps({"files": ["print('safe')\n"], "checks": [{"method": "automated", "rule": "CODE-PY-EVAL", "expected_count": 0}]}))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(testing.main(["register", "--spec", str(spec), "--target", str(root / "target.json"), "--authorize-isolated-synthetic-source"]), 0)
                self.assertEqual(testing.main(["run", "--target", str(root / "target.json"), "--output", str(root / "review")]), 0)
                self.assertEqual(testing.main(["run", "--target", str(root / "target.json"), "--output", str(root / "review")]), 2)
            self.assertEqual(json.loads((root / "review/report.json").read_text())["state"], "PASS")

    def test_optional_strict_file_set_does_not_change_ordinary_scans(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("eval(user_input)\n")
            self.assertEqual(scan(root, Config()), scan(root, Config(), expected_files={"app.py"}))
            with self.assertRaises(ValueError):
                scan(root, Config(), expected_files={"absent.py"})
