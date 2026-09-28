"""Dependency-free golden identity checks; official-schema suite is separate."""
import importlib.util
import json
import unittest
from pathlib import Path

from vulcanary.dashboard import remediation_receipt_valid

ROOT = Path(__file__).parent / "contracts"
spec = importlib.util.spec_from_file_location("contract_fixtures", ROOT / "fixtures.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class ReportContracts(unittest.TestCase):
    def test_production_outputs_match_committed_goldens_including_identities(self):
        actual = fixtures.reports()
        self.assertEqual(set(actual), {path.stem for path in (ROOT / "golden").glob("*.json")})
        for name, document in actual.items():
            with self.subTest(format=name):
                expected = json.loads((ROOT / "golden" / f"{name}.json").read_text(encoding="utf-8"))
                self.assertEqual(document, expected)

    def test_sealed_receipt_is_valid_and_detects_tampering(self):
        receipt = fixtures.reports()["receipt"]
        self.assertTrue(remediation_receipt_valid(receipt))
        receipt["selected_fingerprints"][0] = "0" * 20
        self.assertFalse(remediation_receipt_valid(receipt))


if __name__ == "__main__":
    unittest.main()
