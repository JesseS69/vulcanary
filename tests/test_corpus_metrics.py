import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.corpus_metrics import compare_corpus_reports, load_corpus_manifest, write_comparison


class CorpusMetricsTests(unittest.TestCase):
    def test_manifest_pins_git_corpora_and_prohibits_execution(self) -> None:
        manifest = load_corpus_manifest(Path(__file__).parents[1] / "benchmarks" / "corpora.json")
        self.assertEqual(manifest["corpora"][0]["revision"], "f1291485808b66e20ddb6b01b10dc71b3df8c8ba")
        self.assertTrue(all(item["execution"] == "never" for item in manifest["corpora"]))

    def test_comparison_reports_metric_gap_and_fingerprint_changes(self) -> None:
        baseline = {
            "exposures": [{"fingerprint": "old", "rule_id": "RULE", "path": "app.py", "line": 4, "sink": "eval"}],
            "unmodeled_construct_count": 1,
            "unmodeled_constructs": [{
                "path": "app.py", "category": "cross_module_call",
                "construct": "unresolved return from helper", "sink_line": 4,
            }],
            "analysis_truncations": [{"path": "app.py", "function": "old", "line": 3}], "parse_errors": 0,
            "benchmark": {"true_positives": 1, "false_positives": 0, "false_negatives": 1, "true_negatives": 2},
        }
        candidate = {
            "exposures": [{"fingerprint": "new", "rule_id": "RULE", "path": "app.py", "line": 4, "sink": "eval"}],
            "unmodeled_construct_count": 0, "unmodeled_constructs": [],
            "analysis_truncations": [{"path": "app.py", "function": "helper", "line": 4}], "parse_errors": 0,
            "benchmark": {"true_positives": 2, "false_positives": 0, "false_negatives": 0, "true_negatives": 2},
        }
        comparison = compare_corpus_reports(baseline, candidate)
        self.assertEqual(comparison["delta"]["true_positives"], 1)
        self.assertEqual(comparison["gap_categories"]["delta"]["cross_module_call"], -1)
        self.assertEqual(comparison["fingerprints"]["churn"][0]["before"], "old")
        self.assertEqual(comparison["gap_identities"]["removed"][0]["sink_line"], 4)
        self.assertEqual(comparison["truncation_identities"]["removed"][0]["function"], "old")
        self.assertEqual(comparison["truncation_identities"]["added"][0]["function"], "helper")

    def test_comparison_file_is_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            output = root / "comparison.json"
            baseline.write_text(json.dumps({"exposures": []}), encoding="utf-8")
            candidate.write_text(json.dumps({"exposures": []}), encoding="utf-8")
            write_comparison(baseline, candidate, output)
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], "vulcanary.corpus-comparison.v1")
        self.assertEqual(document["fingerprints"]["churn"], [])
        self.assertEqual(document["gap_identities"], {"added": [], "removed": []})
        self.assertEqual(document["truncation_identities"], {"added": [], "removed": []})


if __name__ == "__main__":
    unittest.main()
