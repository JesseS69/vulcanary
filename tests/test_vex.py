import tempfile
import unittest
from pathlib import Path

from vulcanary.vex import openvex_document, write_openvex


class VexTests(unittest.TestCase):
    def test_reports_observed_dependencies_as_affected_without_claiming_safety(self) -> None:
        finding = {"rule_id": "SCA-GHSA-demo", "category": "dependency", "metadata": {"advisory": "GHSA-demo", "package": "demo", "current_version": "1.0.0", "ecosystem": "npm"}}
        document = openvex_document("demo-repo", [finding, finding])
        self.assertEqual(len(document["statements"]), 1)
        statement = document["statements"][0]
        self.assertEqual(statement["status"], "affected")
        self.assertIn("does not prove safety", statement["status_notes"])
        ecosystem_findings = [
            {"rule_id": "SCA-GO-demo", "category": "dependency", "metadata": {"advisory": "GO-demo", "package": "github.com/gin-gonic/gin", "current_version": "1.9.0", "ecosystem": "Go"}},
            {"rule_id": "SCA-RUST-demo", "category": "dependency", "metadata": {"advisory": "RUST-demo", "package": "regex", "current_version": "1.5.1", "ecosystem": "crates.io"}},
            {"rule_id": "SCA-PHP-demo", "category": "dependency", "metadata": {"advisory": "PHP-demo", "package": "symfony/http-foundation", "current_version": "5.4.0", "ecosystem": "Packagist"}},
            {"rule_id": "SCA-RUBY-demo", "category": "dependency", "metadata": {"advisory": "RUBY-demo", "package": "rack", "current_version": "2.2.3", "ecosystem": "RubyGems"}},
        ]
        products = [item["products"][0]["@id"] for item in openvex_document("demo-repo", ecosystem_findings)["statements"]]
        self.assertEqual(products, [
            "pkg:golang/github.com/gin-gonic/gin@1.9.0", "pkg:cargo/regex@1.5.1",
            "pkg:composer/symfony/http-foundation@5.4.0", "pkg:gem/rack@2.2.3",
        ])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "vex.json"
            write_openvex(document, output)
            self.assertTrue(output.read_text(encoding="utf-8").endswith("\n"))
