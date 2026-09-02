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

    def test_trivy_container_image_is_tracked_separately_without_docker_access(self) -> None:
        findings = self.load("trivy-image", {
            "SchemaVersion": 2, "ArtifactName": "registry.example/demo:1.0", "ArtifactType": "container_image",
            "Results": [{"Target": "alpine 3.19", "Type": "alpine", "Vulnerabilities": [{
                "VulnerabilityID": "CVE-IMAGE-1", "PkgName": "libssl3", "InstalledVersion": "3.1.4-r0",
                "FixedVersion": "3.1.4-r1", "Severity": "HIGH",
            }]}],
        })
        finding = findings[0]
        self.assertEqual(finding.category, "container")
        self.assertEqual(finding.metadata["image"], "registry.example/demo:1.0")
        self.assertEqual(finding.evidence, "libssl3@3.1.4-r0")
        self.assertTrue(finding.path.startswith("container-image/"))

    def test_checkov_array_report_and_path_traversal(self) -> None:
        findings = self.load("checkov", [{"results": {"failed_checks": [{"check_id": "CKV_AWS_1", "check_name": "Encryption", "file_path": "../../secret.tf", "file_line_range": [9, 10], "severity": "HIGH"}]}}])
        self.assertEqual(findings[0].path, "external-report")
        self.assertEqual(findings[0].line, 9)

    def test_zap_report_excludes_response_content(self) -> None:
        findings = self.load("zap", {"site": [{"@host": "example.test", "alerts": [{
            "pluginid": "10010", "alert": "Cookie missing HttpOnly", "riskcode": "2", "desc": "Cookie policy",
            "solution": "Add HttpOnly", "instances": [{"uri": "https://example.test/account", "evidence": "secret-session"}],
        }]}]})
        self.assertEqual((findings[0].category, findings[0].scanner), ("dast", "zap"))
        self.assertNotIn("secret-session", json.dumps(findings[0].to_dict()))

    def test_generic_sarif_report_is_normalized(self) -> None:
        findings = self.load("sarif", {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "Demo Scanner", "rules": [{"id": "R1", "help": {"text": "Fix it"}}]}},
            "results": [{"ruleId": "R1", "level": "error", "message": {"text": "Unsafe setting"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra.tf"}, "region": {"startLine": 8}}}]}],
        }]})
        self.assertEqual((findings[0].scanner, findings[0].line, findings[0].severity), ("demo-scanner", 8, Severity.HIGH))

    def test_prowler_ocsf_skips_passes_and_normalizes_failures(self) -> None:
        findings = self.load("prowler", [{"status": "PASS"}, {
            "status": "FAIL", "severity": "high", "finding_info": {"uid": "aws_s3_public", "title": "Public bucket"},
            "resources": [{"uid": "arn:demo", "name": "bucket", "region": "us-east-1"}],
            "remediation": {"desc": "Disable public access"},
        }])
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0].category, findings[0].metadata["region"]), ("cloud", "us-east-1"))

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

    def test_cli_applies_repository_exclusions_to_imported_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text(json.dumps({"exclude": ["benchmarks/**"]}), encoding="utf-8")
            report = root / "semgrep.json"
            report.write_text(json.dumps({"results": [{
                "check_id": "synthetic.secret", "path": "benchmarks/cases.json", "start": {"line": 1},
                "extra": {"message": "Synthetic benchmark credential", "severity": "ERROR"},
            }]}), encoding="utf-8")
            output = root / "vulcanary.json"
            self.assertEqual(main([str(root), "--offline", "--semgrep-json", str(report), "--json", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["findings"], [])


if __name__ == "__main__":
    unittest.main()
