from __future__ import annotations

import re
import unittest
from pathlib import Path


class V1ReadinessTests(unittest.TestCase):
    def test_readiness_gate_has_only_known_statuses_and_no_untracked_criteria(self) -> None:
        root = Path(__file__).resolve().parents[1]
        document = (root / "docs" / "V1_READINESS.md").read_text(encoding="utf-8")
        blockers = document.split("## Release blockers", 1)[1].split("## Explicitly deferred", 1)[0]
        statuses = re.findall(r"^\| \*\*(Met|Partial|Open|Deferred)\*\* \|", blockers, re.MULTILINE)
        criteria = re.findall(r"^\| \*\*(?:Met|Partial|Open|Deferred)\*\* \| ([^|]+) \| ([^|]+) \|$", blockers, re.MULTILINE)
        self.assertGreaterEqual(len(criteria), 30)
        self.assertEqual(len(statuses), len(criteria))
        self.assertIn("Open", statuses)
        self.assertIn("Partial", statuses)
        self.assertIn("## Standing merge gates through v1", document)
        self.assertIn("## Explicitly deferred from free local-first v1", document)

    def test_readme_links_to_the_readiness_gate(self) -> None:
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn("[v1.0 readiness gate](docs/V1_READINESS.md)", readme)


if __name__ == "__main__":
    unittest.main()
