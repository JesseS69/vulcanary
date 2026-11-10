import copy
import io
from contextlib import redirect_stdout
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import os

from vulcanary import test_inventory as inventory
from vulcanary.security_testing import register, execute
from vulcanary.security_testing import main as run_main


class InventoryTests(unittest.TestCase):
    def test_stat_clock_skew_and_same_handle_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.apk"
            path.write_bytes(b"synthetic")
            real = os.fstat
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
            for changed in (None, "st_ctime_ns", "st_mtime_ns", "st_ino", "st_size"):
                calls = []
                def observed(fd):
                    original = real(fd)
                    result = {name: getattr(original, name) for name in fields}
                    result["st_ctime_ns"] += 1000000
                    if calls and changed:
                        result[changed] += 1
                    calls.append(True)
                    return SimpleNamespace(**result)
                with patch.object(inventory.os, "fstat", side_effect=observed):
                    result = inventory.artifact_identity(path, "apk")
                self.assertEqual(result["state"], "BLOCKED" if changed else "NOT_RUN", changed)

    def test_sixty_fresh_files(self):
        with tempfile.TemporaryDirectory() as directory:
            for index in range(60):
                path = Path(directory) / f"app-{index}.apk"
                path.write_bytes(b"synthetic" * 100)
                self.assertEqual(inventory.artifact_identity(path, "apk")["state"], "NOT_RUN")

    def test_cli_history_and_linked_retest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.run_fixture(root / "before", "eval(user_input)\n")
            self.run_fixture(root / "after", "pass\n")
            output = io.StringIO()
            with redirect_stdout(output):
                code = run_main(["run", "--target", str(root / "before/target.json"), "--output", str(root / "review-before"), "--history", str(root / "history")])
            self.assertEqual(code, 1)
            first = json.loads(output.getvalue().splitlines()[0])["record_id"]
            output = io.StringIO()
            with redirect_stdout(output):
                code = run_main(["run", "--target", str(root / "after/target.json"), "--output", str(root / "review-after"), "--history", str(root / "history"), "--previous", first])
            self.assertEqual(code, 0)
            comparison = json.loads(output.getvalue().splitlines()[0])["comparison"]
            self.assertFalse(comparison["compatible"])
            self.assertEqual(comparison["transitions"], [])
            self.assertEqual(json.loads((root / "review-before/report.json").read_text())["state"], "FAIL")

    def run_fixture(self, root, source):
        root.mkdir()
        spec = root / "spec.json"
        spec.write_text(json.dumps({"files": [source], "checks": [
            {"method": "automated", "rule": "CODE-PY-EVAL", "expected_count": 0}]}))
        register(spec, root / "target.json", authorized=True)
        return execute(root / "target.json")

    def test_artifact_identity_changes_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.apk"
            path.write_bytes(b"synthetic artifact")
            with patch("socket.socket", side_effect=AssertionError("network")), patch("subprocess.Popen", side_effect=AssertionError("execution")):
                first = inventory.artifact_identity(path, "apk")
                path.write_bytes(b"different artifact")
                second = inventory.artifact_identity(path, "apk")
            self.assertNotEqual(first["content_sha256"], second["content_sha256"])
            self.assertEqual(first["state"], "NOT_RUN")
            self.assertFalse(first["executed"])
            self.assertNotIn("private", json.dumps(first))

    def test_missing_and_oversized_artifacts_are_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.ipa"
            self.assertEqual(inventory.artifact_identity(path, "ipa")["state"], "BLOCKED")
            path.write_bytes(b"12345")
            with patch.object(inventory, "MAX_ARTIFACT_BYTES", 4):
                self.assertEqual(inventory.artifact_identity(path, "ipa")["state"], "BLOCKED")

    def test_backend_reference_is_unverified_and_not_echoed(self):
        with patch("socket.socket", side_effect=AssertionError("network")):
            result = inventory.backend_identity("https://private.invalid?token=PRIVATE_MARKER")
        self.assertEqual(result["identity_verification"], "operator-reference-unverified")
        self.assertEqual(result["state"], "NOT_RUN")
        self.assertNotIn("PRIVATE_MARKER", json.dumps(result))

    def test_real_failure_fix_retest_preserves_old_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = self.run_fixture(root / "before", "eval(user_input)\n")
            after = self.run_fixture(root / "after", "print('clean')\n")
            first = inventory.append_run(root / "history", before)
            path = root / "history" / (first["record_id"] + ".json")
            original = path.read_bytes()
            second = inventory.append_run(root / "history", after, first["record_id"])
            self.assertFalse(second["comparison"]["compatible"])
            self.assertEqual(second["comparison"]["transitions"], [])
            self.assertTrue(second["comparison"]["target_changed"])
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(inventory.append_run(root / "history", before)["record_id"], first["record_id"])
            self.assertEqual(inventory.load_record(root / "history", second["record_id"])["previous"], first["record_id"])

    def test_changed_plan_or_analyzer_never_claims_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.run_fixture(Path(directory) / "fixture", "eval(x)\n")
            before = inventory.summarize(report)
            for key in ("plan_sha256", "implementation_sha256", "ruleset_digest"):
                after = copy.deepcopy(before)
                after[key] = "0" * 64
                after["checks"][0]["state"] = "PASS"
                result = inventory.compare(before, after)
                self.assertFalse(result["compatible"])
                self.assertEqual(result["transitions"], [])

    def test_tampering_or_truncation_blocks_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = self.run_fixture(root / "fixture", "eval(x)\n")
            first = inventory.append_run(root / "history", report)
            path = root / "history" / (first["record_id"] + ".json")
            path.write_text('{"changed":true}')
            with self.assertRaises(ValueError):
                inventory.append_run(root / "history", report, first["record_id"])
            path.write_text('{')
            with self.assertRaises(ValueError):
                inventory.load_record(root / "history", first["record_id"])

    def test_false_pass_and_path_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = self.run_fixture(root / "fixture", "pass\n")
            report["checks"][0]["executed"] = False
            with self.assertRaises(ValueError):
                inventory.append_run(root / "history", report)
            with self.assertRaises(ValueError):
                inventory.load_record(root, "../private")

    def test_blocked_and_unexecuted_are_not_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = inventory.summarize(self.run_fixture(Path(directory) / "fixture", "eval(x)\n"))
            for state, expected in (("BLOCKED", "blocked"), ("NOT_RUN", "not_comparable"), ("DEFERRED", "not_comparable"), ("FAIL", "persistent_failure")):
                after = copy.deepcopy(summary)
                after["checks"][0]["state"] = state
                self.assertEqual(inventory.compare(summary, after)["transitions"][0]["result"], expected)
