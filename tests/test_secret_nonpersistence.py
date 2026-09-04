from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from vulcanary.adapters import import_document
from vulcanary.cli import main
from vulcanary.config import Config
from vulcanary.dashboard import DashboardState, remediation_receipt
from vulcanary.history_secrets import scan_history
from vulcanary.reporters import (
    render_console,
    render_github_annotations,
    render_markdown_summary,
    write_json,
    write_sarif,
)
from vulcanary.scanners import scan
from vulcanary.tickets import finding_ticket, ticket_csv, ticket_markdown
from vulcanary.vex import openvex_document


SENTINEL = "AKIAZ9Y8X7W6V5U4T3S2"  # gitleaks:allow -- synthetic noncredential


class SecretNonPersistenceTests(unittest.TestCase):
    def assert_secret_absent(self, value: object, surface: str) -> None:
        serialized = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        self.assertNotIn(SENTINEL, serialized, f"plaintext secret reached {surface}")

    def test_plaintext_secret_never_reaches_outputs_or_local_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root = workspace / "repository"
            root.mkdir()
            (root / "settings.env").write_text(f"AWS_ACCESS_KEY_ID={SENTINEL}\n", encoding="utf-8")

            findings = scan(root, Config())
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].evidence, "[redacted]")
            self.assert_secret_absent(findings[0].to_dict(), "finding")

            normalized = workspace / "report.json"
            sarif = workspace / "report.sarif"
            write_json(findings, normalized)
            write_sarif(findings, sarif)
            surfaces = {
                "normalized JSON": normalized.read_text(encoding="utf-8"),
                "SARIF": sarif.read_text(encoding="utf-8"),
                "console": render_console(findings),
                "GitHub annotations": render_github_annotations(findings),
                "Markdown summary": render_markdown_summary(findings, "repository"),
                "OpenVEX": json.dumps(openvex_document("repository", [findings[0].to_dict()])),
            }
            ticket = finding_ticket({**findings[0].to_dict(), "repository": "repository"})
            surfaces["ticket record"] = json.dumps(ticket)
            surfaces["ticket Markdown"] = ticket_markdown(ticket)
            surfaces["ticket CSV"] = ticket_csv(ticket)
            for name, content in surfaces.items():
                self.assert_secret_absent(content, name)

            history = workspace / "dashboard-history.json"
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                state = DashboardState(history)
                state.scan_repository(root)
            self.assert_secret_absent(state.snapshot(), "dashboard snapshot")
            self.assert_secret_absent(history.read_text(encoding="utf-8"), "dashboard history")

            receipt = remediation_receipt({
                "repository": str(root), "branch": "codex/synthetic", "files": ["settings.env"],
                "validation": {"passed": True, "remaining": [], "finding_count": 0},
                "verification": {"passed": True, "skipped": True, "results": []},
            }, [findings[0].fingerprint])
            state.record_remediation("verified", receipt)
            self.assert_secret_absent(receipt, "remediation receipt")
            self.assert_secret_absent(history.read_text(encoding="utf-8"), "receipt history")

            stdout, stderr = io.StringIO(), io.StringIO()
            cli_json, cli_sarif = workspace / "cli.json", workspace / "cli.sarif"
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([str(root), "--offline", "--json", str(cli_json), "--sarif", str(cli_sarif)])
            self.assertEqual(exit_code, 1)
            for name, content in {
                "CLI stdout": stdout.getvalue(), "CLI stderr": stderr.getvalue(),
                "CLI JSON": cli_json.read_text(encoding="utf-8"),
                "CLI SARIF": cli_sarif.read_text(encoding="utf-8"),
            }.items():
                self.assert_secret_absent(content, name)

    def test_external_and_history_gitleaks_payloads_discard_plaintext(self) -> None:
        report = [{
            "RuleID": "generic-api-key", "Description": "Synthetic key", "File": "settings.env",
            "StartLine": 1, "Secret": SENTINEL, "Match": f"TOKEN={SENTINEL}",
            "Commit": "a" * 40, "Date": "2026-01-01T00:00:00Z",
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            executable = root / "gitleaks.exe"
            executable.write_bytes(b"synthetic executable fixture")

            imported = import_document("gitleaks", report, root)
            self.assertEqual(imported[0].evidence, "[redacted]")
            self.assert_secret_absent([finding.to_dict() for finding in imported], "Gitleaks adapter")

            completed = CompletedProcess([], 1, json.dumps(report), "")
            with (
                patch("vulcanary.history_secrets.git_head", return_value="a" * 40),
                patch("vulcanary.history_secrets.subprocess.run", return_value=completed),
            ):
                history = scan_history(root, executable)
            self.assert_secret_absent(history, "history exposure report")
            self.assertFalse(history["findings"][0]["metadata"]["secret_retained"])


if __name__ == "__main__":
    unittest.main()
