import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.cli import main
from vulcanary.config import Config
from vulcanary.dashboard import DashboardState
from vulcanary.models import Severity
from vulcanary.scanners import scan


class ScannerTests(unittest.TestCase):
    def test_detects_code_secret_and_iac(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text('token = "AKIAABCDEFGHIJKLMNOP"\nvalue = eval(user_input)\n', encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:3.12\nUSER root\n", encoding="utf-8")
            findings = scan(root, Config())
            self.assertEqual({f.rule_id for f in findings}, {"SECRET-AWS-KEY", "CODE-PY-EVAL", "IAC-DOCKER-ROOT"})
            secret = next(f for f in findings if f.category == "secret")
            self.assertEqual(secret.evidence, "[redacted]")

    def test_exclusions_and_ignored_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            vendor.mkdir()
            (vendor / "bad.js").write_text("eval(input)", encoding="utf-8")
            (root / "main.js").write_text("eval(input)", encoding="utf-8")
            config = Config(exclude=["vendor/**"], ignored_rules={"CODE-JS-EVAL"})
            self.assertEqual(scan(root, config), [])

    def test_excluded_directories_are_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependencies = root / "nested" / "node_modules" / "package"
            dependencies.mkdir(parents=True)
            (dependencies / "bad.js").write_text("eval(input)", encoding="utf-8")
            self.assertEqual(scan(root, Config()), [])

    def test_cli_policy_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            config = root / ".vulcanary.json"
            config.write_text(json.dumps({"fail_on": "medium"}), encoding="utf-8")
            json_path = root / "report.json"
            sarif_path = root / "report.sarif"
            self.assertEqual(main([str(root), "--json", str(json_path), "--sarif", str(sarif_path)]), 1)
            self.assertEqual(json.loads(json_path.read_text())["findings"][0]["severity"], "medium")
            self.assertEqual(json.loads(sarif_path.read_text())["version"], "2.1.0")

    def test_default_threshold_allows_medium(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            self.assertEqual(main([str(root)]), 0)

    def test_dashboard_aggregates_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            state = DashboardState()
            state.scan_repository(root)
            snapshot = state.snapshot()
            self.assertEqual(snapshot["summary"]["total"], 1)
            self.assertEqual(snapshot["summary"]["counts"]["medium"], 1)
            self.assertEqual(snapshot["findings"][0]["repository"], root.name)


if __name__ == "__main__":
    unittest.main()
