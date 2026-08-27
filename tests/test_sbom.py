import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.dependencies import Package
from vulcanary.sbom import cyclonedx_document, write_cyclonedx


class SbomTests(unittest.TestCase):
    def test_generates_cyclonedx_inventory_and_advisory_relationships(self) -> None:
        packages = [
            Package("@scope/direct", "1.2.3", "npm", "private/package-lock.json", True, "npm"),
            Package("transitive", "2.0.0", "npm", "private/package-lock.json", False, "npm"),
            Package("requests", "2.32.0", "PyPI", "private/requirements.txt", True, "pip"),
        ]
        findings = [{
            "rule_id": "SCA-GHSA-demo", "title": "Demo advisory", "severity": "high", "category": "dependency",
            "remediation": "Upgrade transitive.", "metadata": {
                "package": "transitive", "current_version": "2.0.0", "ecosystem": "npm", "manager": "npm",
                "direct": False, "advisory": "GHSA-demo", "reachability": {"status": "parent_import_observed"},
            },
        }]
        document = cyclonedx_document("demo-app", packages, findings)
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.5")
        references = {item["bom-ref"] for item in document["components"]}
        self.assertIn("pkg:npm/%40scope/direct@1.2.3", references)
        self.assertIn("pkg:pypi/requests@2.32.0", references)
        self.assertEqual(document["vulnerabilities"][0]["affects"], [{"ref": "pkg:npm/transitive@2.0.0"}])
        self.assertEqual(document["vulnerabilities"][0]["properties"][0]["value"], "parent_import_observed")
        root_dependencies = document["dependencies"][0]["dependsOn"]
        self.assertIn("pkg:npm/%40scope/direct@1.2.3", root_dependencies)
        self.assertNotIn("pkg:npm/transitive@2.0.0", root_dependencies)
        self.assertNotIn("private", json.dumps(document))

    def test_writes_formatted_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "sbom.json"
            write_cyclonedx(cyclonedx_document("empty", [], []), destination)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8"))["metadata"]["component"]["name"], "empty")
            self.assertTrue(destination.read_text(encoding="utf-8").endswith("\n"))


if __name__ == "__main__":
    unittest.main()
