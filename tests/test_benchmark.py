import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.config import Config
from vulcanary.scanners import RULES, scan


class AccuracyBenchmarkTests(unittest.TestCase):
    def test_every_builtin_rule_detects_vulnerable_and_ignores_safe_fixture(self) -> None:
        document = json.loads((Path(__file__).parents[1] / "benchmarks" / "cases.json").read_text(encoding="utf-8"))
        self.assertEqual({case["rule_id"] for case in document}, {rule.id for rule in RULES})
        self.assertEqual(len(document), len(RULES))
        for case in document:
            with self.subTest(rule=case["rule_id"]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / case["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(case["vulnerable"], encoding="utf-8")
                vulnerable_rules = {finding.rule_id for finding in scan(root, Config())}
                self.assertIn(case["rule_id"], vulnerable_rules)
                target.write_text(case["safe"], encoding="utf-8")
                safe_rules = {finding.rule_id for finding in scan(root, Config())}
                self.assertNotIn(case["rule_id"], safe_rules)


if __name__ == "__main__":
    unittest.main()
