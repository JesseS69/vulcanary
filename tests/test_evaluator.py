import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary.evaluator import latest_same_major, parent_candidates


class ParentEvaluatorTests(unittest.TestCase):
    def test_groups_advisories_by_declared_direct_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"expo": "~54.0.36", "direct": "^2.0.0"},
            }), encoding="utf-8")
            findings = [
                {"repository_path": str(root), "metadata": {"package": "undici", "advisory": "GHSA-one", "parent_packages": ["expo"]}},
                {"repository_path": str(root), "metadata": {"package": "postcss", "advisory": "GHSA-two", "parent_packages": ["expo", "not-direct"]}},
            ]
            candidates = parent_candidates(findings, str(root))

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["package"], "expo")
        self.assertEqual(candidates[0]["specification"], "~54.0.36")
        self.assertEqual(candidates[0]["advisories"], ["GHSA-one", "GHSA-two"])
        self.assertEqual(candidates[0]["vulnerable_packages"], ["postcss", "undici"])

    def test_selects_latest_version_within_declared_major(self) -> None:
        completed = subprocess.CompletedProcess(
            ["npm"], 0, stdout=json.dumps(["54.0.36", "54.0.40", "55.0.0"]), stderr="",
        )
        with patch("vulcanary.evaluator._run", return_value=completed):
            version = latest_same_major(Path("."), "expo", "~54.0.36")
        self.assertEqual(version, "54.0.40")

    def test_pre_one_packages_stay_within_the_current_minor(self) -> None:
        completed = subprocess.CompletedProcess(
            ["npm"], 0, stdout=json.dumps(["0.81.5", "0.81.7", "0.87.1"]), stderr="",
        )
        with patch("vulcanary.evaluator._run", return_value=completed):
            version = latest_same_major(Path("."), "react-native", "0.81.5")
        self.assertEqual(version, "0.81.7")


if __name__ == "__main__":
    unittest.main()
