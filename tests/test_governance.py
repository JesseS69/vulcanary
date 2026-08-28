import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from unittest.mock import patch

from vulcanary.cli import main
from vulcanary.config import Config, Suppression
from vulcanary.dashboard import DashboardState
from vulcanary.governance import suppression_findings
from vulcanary.scanners import scan


class GovernanceTests(unittest.TestCase):
    def test_active_exception_suppresses_only_its_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.js"
            source.write_text("element.innerHTML = input\n", encoding="utf-8")
            fingerprint = scan(root, Config())[0].fingerprint
            self._write_config(root, fingerprint, expires="2099-01-01")
            config = Config.load(root)
            self.assertEqual(scan(root, config), [])
            self.assertEqual(suppression_findings(config), [])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(root), "--offline"]), 0)

    def test_expired_exception_restores_finding_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input\n", encoding="utf-8")
            fingerprint = scan(root, Config())[0].fingerprint
            self._write_config(root, fingerprint, expires="2000-01-01")
            config = Config.load(root)
            self.assertEqual(len(scan(root, config)), 1)
            governance = suppression_findings(config)
            self.assertEqual(governance[0].rule_id, "GOV-SUPPRESSION-EXPIRED")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(root), "--offline"]), 1)

    def test_expiring_window_and_strict_validation(self) -> None:
        suppression = Suppression("a" * 20, "deferred", "security@example.com", "Waiting for upstream patch.", date(2026, 9, 5))
        self.assertEqual(suppression.status(date(2026, 8, 27)), "expiring")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_config(root, "a" * 20, owner="", expires="2099-01-01")
            with self.assertRaisesRegex(ValueError, "owner is required"):
                Config.load(root)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(root), "--offline"]), 2)

    def test_dashboard_persists_exception_change_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            (root / "main.js").write_text("element.innerHTML = input\n", encoding="utf-8")
            fingerprint = scan(root, Config())[0].fingerprint
            history = Path(directory) / "history.json"
            self._write_config(root, fingerprint, owner="alice@example.com", expires="2099-01-01")
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                state = DashboardState(history)
                baseline = state.scan_repository(root)
                self.assertTrue(baseline.suppression_change["baseline"])
                self._write_config(root, fingerprint, owner="bob@example.com", expires="2099-01-01")
                changed = state.scan_repository(root)
                self.assertEqual(changed.suppression_change["changed"][0]["owner"], "bob@example.com")
                restored = DashboardState(history)
                self.assertEqual(restored.suppression_audit[-1]["action"], "changed")
                self.assertEqual(restored.suppression_audit[-1]["owner"], "bob@example.com")

    def test_dashboard_registers_governed_inline_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("// vulcanary:ignore CODE-JS-EVAL owner=alice@example.com expires=2099-01-01 -- Input is a reviewed static expression.\neval(input)\n", encoding="utf-8")
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                result = DashboardState().scan_repository(root)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.suppressions[0]["scope"], "inline")
            self.assertEqual(result.suppressions[0]["path"], "main.js")

    def test_legacy_rule_and_fingerprint_ignores_are_visible(self) -> None:
        config = Config(ignored_rules={"CODE-JS-EVAL"}, ignored_fingerprints={"a" * 20})
        findings = suppression_findings(config)
        self.assertEqual({item.rule_id for item in findings}, {"GOV-LEGACY-RULE-IGNORE", "GOV-LEGACY-SUPPRESSION"})
        register = config.suppression_register()
        self.assertEqual({item["scope"] for item in register}, {"rule", "fingerprint"})

    @staticmethod
    def _write_config(root: Path, fingerprint: str, owner: str = "security@example.com", expires: str = "2099-01-01") -> None:
        (root / ".vulcanary.json").write_text(json.dumps({
            "suppressions": [{
                "fingerprint": fingerprint, "reason": "deferred", "owner": owner,
                "justification": "Waiting for a verified upstream remediation.", "expires": expires,
            }],
        }), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
