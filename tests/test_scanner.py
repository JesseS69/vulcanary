import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary.cli import main
from vulcanary.config import Config
from vulcanary.dashboard import DashboardState
from vulcanary.dependencies import discover_packages, scan_dependencies
from vulcanary.fixes import preview
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

    def test_loads_argument_array_verification_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text(json.dumps({
                "verify_commands": [["python", "-m", "pytest"], ["python", "-m", "build"]],
                "verify_timeout_seconds": 45,
            }), encoding="utf-8")
            config = Config.load(root)
            self.assertEqual(config.verify_commands[0], ["python", "-m", "pytest"])
            self.assertEqual(config.verify_timeout_seconds, 45)

    def test_inline_rule_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("// vulcanary:ignore CODE-JS-EVAL\neval(input)\n", encoding="utf-8")
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

    def test_discovers_pinned_dependencies_and_skips_generated_copies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = {"packages": {"node_modules/lodash": {"version": "4.17.20"}}}
            (root / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            generated = root / ".expo" / "archive"
            generated.mkdir(parents=True)
            (generated / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            packages = discover_packages(root)
            self.assertEqual([(item.name, item.version, item.ecosystem) for item in packages], [("lodash", "4.17.20", "npm")])

    def test_normalizes_osv_advisories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            batch = {"results": [{"vulns": [{"id": "GHSA-test"}]}]}
            record = {"summary": "Demo advisory", "database_specific": {"severity": "CRITICAL"}, "affected": [{"package": {"name": "demo"}, "ranges": [{"events": [{"fixed": "1.1.0"}]}]}]}
            with patch("vulcanary.dependencies._json_request", side_effect=[batch, record]):
                findings, warning = scan_dependencies(root)
            self.assertIsNone(warning)
            self.assertEqual(findings[0].severity, Severity.CRITICAL)
            self.assertIn("1.1.0", findings[0].remediation)

    def test_fix_preview_separates_safe_and_manual_findings(self) -> None:
        findings = [
            {"fingerprint": "safe", "title": "Safe", "repository": "app", "repository_path": "C:/app", "metadata": {"fix_eligible": True, "package": "demo", "current_version": "1.0.0", "fixed_version": "1.1.0", "advisory": "GHSA-safe"}},
            {"fingerprint": "manual", "title": "Manual", "repository": "app", "repository_path": "C:/app", "metadata": {"fix_eligible": False}},
        ]
        plan = preview(findings, ["safe", "manual"])
        self.assertEqual(len(plan["changes"]), 1)
        self.assertEqual(len(plan["blocked"]), 1)


if __name__ == "__main__":
    unittest.main()
