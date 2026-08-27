import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.adapters import AdapterError, import_report
from vulcanary.cli import main
from vulcanary.models import Severity


class AdapterTests(unittest.TestCase):
    def load(self, scanner: str, document: object):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "external.json"
            report.write_text(json.dumps(document), encoding="utf-8")
            return import_report(scanner, report, root)

    def test_semgrep(self) -> None:
        findings = self.load("semgrep", {"results": [{"check_id": "python.eval", "path": "app.py", "start": {"line": 7}, "extra": {"message": "Avoid eval", "severity": "ERROR", "metadata": {"confidence": "HIGH"}}}]})
        self.assertEqual((findings[0].rule_id, findings[0].severity, findings[0].line), ("SEMGREP-python.eval", Severity.HIGH, 7))

    def test_gitleaks_never_retains_secret(self) -> None:
        findings = self.load("gitleaks", [{"RuleID": "generic-api-key", "Description": "API key", "File": "config.js", "StartLine": 2, "Secret": "do-not-store-me", "Match": "token=do-not-store-me"}])
        serialized = json.dumps(findings[0].to_dict())
        self.assertEqual(findings[0].evidence, "[redacted]")
        self.assertNotIn("do-not-store-me", serialized)

    def test_trivy_vulnerability_and_misconfiguration(self) -> None:
        findings = self.load("trivy", {"SchemaVersion": 2, "Results": [{"Target": "package-lock.json", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "demo", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "CRITICAL"}], "Misconfigurations": [{"ID": "AVD-1", "Title": "Unsafe config", "Severity": "HIGH", "CauseMetadata": {"StartLine": 4}}]}]})
        self.assertEqual({finding.category for finding in findings}, {"dependency", "iac"})
        self.assertEqual(max(finding.severity for finding in findings), Severity.CRITICAL)

    def test_trivy_schema_versioned_report_may_have_no_results(self) -> None:
        self.assertEqual(self.load("trivy", {"SchemaVersion": 2, "ArtifactType": "filesystem"}), [])

    def test_checkov_array_report_and_path_traversal(self) -> None:
        findings = self.load("checkov", [{"results": {"failed_checks": [{"check_id": "CKV_AWS_1", "check_name": "Encryption", "file_path": "../../secret.tf", "file_line_range": [9, 10], "severity": "HIGH"}]}}])
        self.assertEqual(findings[0].path, "external-report")
        self.assertEqual(findings[0].line, 9)

    def test_malformed_report_fails_closed(self) -> None:
        with self.assertRaises(AdapterError):
            self.load("semgrep", {"unexpected": []})

    def test_cli_import_is_deduplicated_and_gated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "gitleaks.json"
            report.write_text(json.dumps([{"RuleID": "key", "Description": "Key", "File": "app.env", "StartLine": 1, "Secret": "hidden"}]), encoding="utf-8")
            output = root / "vulcanary.json"
            self.assertEqual(main([str(root), "--offline", "--gitleaks-json", str(report), "--gitleaks-json", str(report), "--json", str(output)]), 1)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(document["findings"]), 1)
            self.assertNotIn("hidden", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
