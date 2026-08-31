import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary import evaluator
from vulcanary.evaluator import create_expo_migration_branch, latest_same_major, parent_candidates, scoped_override_candidates


class ParentEvaluatorTests(unittest.TestCase):
    def test_scoped_override_candidates_require_one_tooling_parent(self) -> None:
        repository = str(Path("demo").resolve())
        findings = [{
            "fingerprint": "a" * 20, "repository_path": repository,
            "metadata": {
                "package": "uuid", "current_version": "7.0.3", "fixed_version": "11.1.1",
                "advisory": "GHSA-demo", "direct": False,
                "usage": {"classification": "tooling_path_via_runtime_parent"},
                "dependency_paths": [["expo@55", "xcode@3.0.1", "uuid@7.0.3"]],
            },
        }]
        self.assertEqual(scoped_override_candidates(findings, repository)[0]["parent"], "xcode")
        findings[0]["metadata"]["usage"]["classification"] = "runtime_parent_observed"
        self.assertEqual(scoped_override_candidates(findings, repository), [])

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

    def test_migration_branch_rejects_an_unevaluated_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"dependencies": {"expo": "~54.0.36"}}), encoding="utf-8")
            with patch("vulcanary.evaluator.latest_same_major", return_value="55.0.30"):
                with self.assertRaisesRegex(ValueError, "not the evaluated"):
                    create_expo_migration_branch(str(root), "55.0.29")

    def test_migration_branch_leaves_reviewable_changes_uncommitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package.json"
            package.write_text(json.dumps({"dependencies": {"expo": "~54.0.36"}}) + "\n", encoding="utf-8")
            self._initialize_repository(root)
            real_run = evaluator._run

            def run(command, cwd, timeout, environment=None):
                if command[0] == "npm":
                    package.write_text(json.dumps({"dependencies": {"expo": "~55.0.30"}}) + "\n", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if Path(command[0]).name in {"expo", "expo.cmd"}:
                    (root / "app.json").write_text('{"expo": {}}\n', encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return real_run(command, cwd, timeout, environment)

            with patch("vulcanary.evaluator.latest_same_major", return_value="55.0.30"), patch("vulcanary.evaluator._run", side_effect=run):
                created = create_expo_migration_branch(str(root), "55.0.30")

            self.assertTrue(created["branch"].startswith("vulcanary/migrate-expo-55.0.30-"))
            self.assertEqual(created["original_branch"], "main")
            self.assertIn("package.json", created["changed_files"])
            self.assertEqual(real_run(["git", "branch", "--show-current"], root, 30).stdout.strip(), created["branch"])
            self.assertTrue(real_run(["git", "status", "--porcelain"], root, 30).stdout.strip())

    def test_failed_migration_restores_original_branch_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package.json"
            original = json.dumps({"dependencies": {"expo": "~54.0.36"}}) + "\n"
            package.write_text(original, encoding="utf-8")
            self._initialize_repository(root)
            real_run = evaluator._run

            def run(command, cwd, timeout, environment=None):
                if command[0] == "npm":
                    package.write_text('{"dependencies": {"expo": "broken"}}\n', encoding="utf-8")
                    (root / "generated.tmp").write_text("temporary\n", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 1, "", "failed")
                return real_run(command, cwd, timeout, environment)

            with patch("vulcanary.evaluator.latest_same_major", return_value="55.0.30"), patch("vulcanary.evaluator._run", side_effect=run):
                with self.assertRaisesRegex(ValueError, "original branch was restored"):
                    create_expo_migration_branch(str(root), "55.0.30")

            self.assertEqual(real_run(["git", "branch", "--show-current"], root, 30).stdout.strip(), "main")
            self.assertEqual(package.read_text(encoding="utf-8"), original)
            self.assertFalse((root / "generated.tmp").exists())
            self.assertFalse(real_run(["git", "branch", "--list", "vulcanary/migrate-expo-*"], root, 30).stdout.strip())

    @staticmethod
    def _initialize_repository(root: Path) -> None:
        subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "tests@vulcanary.local"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Vulcanary Tests"], cwd=root, check=True)
        subprocess.run(["git", "add", "package.json"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-m", "fixture"], cwd=root, check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
