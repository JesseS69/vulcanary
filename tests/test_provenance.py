import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.provenance import scan_provenance, write_provenance


class ProvenanceTests(unittest.TestCase):
    def test_hashes_artifacts_without_claiming_a_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "vulcanary.json"
            report.write_text('{"findings": []}\n', encoding="utf-8")
            document = scan_provenance("demo", [report, root / "missing.json"], "a" * 64)
            self.assertEqual(document["_type"], "https://in-toto.io/Statement/v1")
            self.assertTrue(document["predicate"]["unsigned"])
            self.assertEqual(document["subject"], [{
                "name": "vulcanary.json", "digest": {"sha256": hashlib.sha256(report.read_bytes()).hexdigest()},
            }])
            destination = root / "provenance.json"
            write_provenance(document, destination)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8"))["predicate"]["scanner"]["rulesetDigest"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
