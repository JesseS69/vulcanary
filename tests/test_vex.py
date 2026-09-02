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
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "vex.json"
            write_openvex(document, output)
            self.assertTrue(output.read_text(encoding="utf-8").endswith("\n"))
