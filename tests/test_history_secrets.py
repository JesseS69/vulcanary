import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from vulcanary.dashboard import DashboardState
from vulcanary.history_secrets import HistoryScanError, scan_history, validate_executable


class HistorySecretTests(unittest.TestCase):
    def test_executable_must_be_an_explicit_existing_absolute_file(self) -> None:
        with self.assertRaisesRegex(HistoryScanError, "absolute path"):
            validate_executable("gitleaks")

    def test_history_scan_is_redacted_location_collapsed_and_oldest_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            executable = root / "trusted-gitleaks.exe"
            executable.write_bytes(b"binary")
            older, newer = "a" * 40, "b" * 40
            report = [
                {"RuleID": "generic", "Description": "Key", "File": "config.env", "StartLine": 2, "Secret": "new-secret", "Match": "TOKEN=new-secret", "Commit": newer, "Date": "2026-02-01T00:00:00Z"},
                {"RuleID": "generic", "Description": "Key", "File": "config.env", "StartLine": 2, "Secret": "old-secret", "Match": "TOKEN=old-secret", "Commit": older, "Date": "2026-01-01T00:00:00Z"},
            ]
            completed = CompletedProcess([], 1, json.dumps(report), "")
            with patch("vulcanary.history_secrets.git_head", return_value=newer), patch("vulcanary.history_secrets.subprocess.run", return_value=completed) as run:
                result = scan_history(root, executable)
            self.assertEqual(len(result["findings"]), 1)
            finding = result["findings"][0]
            self.assertEqual(finding["evidence"], "[redacted]")
            self.assertEqual(finding["severity"], "unknown")
            self.assertEqual(finding["metadata"]["first_commit"], older)
            self.assertEqual(finding["metadata"]["occurrence_count"], 2)
            serialized = json.dumps(result)
            self.assertNotIn("old-secret", serialized)
            self.assertNotIn("new-secret", serialized)
            command = run.call_args.args[0]
            self.assertIn("--redact=100", command)
            self.assertIn("--report-path=-", command)
            self.assertIn("--log-opts=--no-textconv --full-history --all --diff-filter=tuxdb", command)
            self.assertEqual(run.call_args.kwargs["cwd"], Path.home())

    def test_incremental_scan_uses_only_the_new_commit_range(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / ".git").mkdir()
            executable = root / "gitleaks"; executable.write_bytes(b"binary")
            older, newer = "a" * 40, "b" * 40
            completed = CompletedProcess([], 0, "[]", "")
            with patch("vulcanary.history_secrets.git_head", return_value=newer), patch("vulcanary.history_secrets._is_ancestor", return_value=True), patch("vulcanary.history_secrets.subprocess.run", return_value=completed) as run:
                result = scan_history(root, executable, older)
            self.assertEqual(result["mode"], "incremental")
            self.assertIn(f"--log-opts=--no-textconv {older}..{newer}", run.call_args.args[0])

    def test_rotation_acknowledgement_has_no_sla_and_survives_history_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory) / "history.json")
            fingerprint = "a" * 20
            state.history_exposures = {directory: {fingerprint: {"fingerprint": fingerprint, "status": "rotation_required", "metadata": {"history_exposure": True}}}}
            state.acknowledge_history_rotation(directory, fingerprint, "security owner", "2026-09-03")
            restored = DashboardState(Path(directory) / "history.json")
            acknowledgement = restored.history_acknowledgements[directory][fingerprint]
            self.assertEqual(acknowledgement["owner"], "security owner")
            self.assertEqual(acknowledgement["rotated_at"], "2026-09-03")
            exposure = restored.history_exposures[directory][fingerprint]
            self.assertNotIn("deadline", exposure)
            self.assertNotIn("sla_days", exposure)

    def test_rotation_acknowledgement_is_repository_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = str(Path(directory) / "first")
            second = str(Path(directory) / "second")
            fingerprint = "b" * 20
            record = {"fingerprint": fingerprint, "status": "rotation_required", "metadata": {"history_exposure": True}}
            state = DashboardState()
            state.history_exposures = {first: {fingerprint: dict(record)}, second: {fingerprint: dict(record)}}
            state.acknowledge_history_rotation(first, fingerprint, "first owner", "2026-09-03")
            snapshot = state.snapshot()["history_secrets"]["exposures"]
            acknowledgements = {item["repository_path"]: item["acknowledgement"] for item in snapshot}
            self.assertIsNotNone(acknowledgements[first])
            self.assertIsNone(acknowledgements[second])


if __name__ == "__main__":
    unittest.main()
