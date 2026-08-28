import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary.dashboard import DashboardState, remediation_receipt, remediation_receipt_valid
from vulcanary.fixes import apply_changes, commit_changes, preview, run_verification


class FixWorkflowTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def _initialize_repository(self, root: Path) -> dict:
        package = {
            "name": "vulcanary-disposable-target",
            "private": True,
            "dependencies": {"demo-package": "^1.0.0"},
        }
        lock = {
            "name": package["name"],
            "lockfileVersion": 3,
            "packages": {
                "": {"name": package["name"], "dependencies": {"demo-package": "^1.0.0"}},
                "node_modules/demo-package": {"version": "1.0.0"},
            },
        }
        (root / "package.json").write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
        (root / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.name", "Vulcanary Test")
        self._git(root, "config", "user.email", "vulcanary-test@example.invalid")
        self._git(root, "add", "package.json", "package-lock.json")
        self._git(root, "commit", "-m", "fixture: vulnerable dependency")
        return package

    def _plan(self, root: Path) -> dict:
        finding = {
            "fingerprint": "safe-demo-fix",
            "title": "Disposable dependency advisory",
            "repository": root.name,
            "repository_path": str(root),
            "metadata": {
                "fix_eligible": True,
                "fix_strategy": "dependency",
                "package": "demo-package",
                "current_version": "1.0.0",
                "fixed_version": "1.1.0",
                "advisory": "GHSA-disposable-test",
            },
        }
        return preview([finding], [finding["fingerprint"]])

    def test_safe_fix_runs_on_an_isolated_branch_and_commits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._initialize_repository(root)
            original_commit = self._git(root, "rev-parse", "HEAD")
            plan = self._plan(root)
            real_run = subprocess.run

            def run_without_network(command, **kwargs):
                if Path(command[0]).stem.lower() != "npm":
                    return real_run(command, **kwargs)
                updated_lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))
                updated_lock["packages"][""]["dependencies"]["demo-package"] = "^1.1.0"
                updated_lock["packages"]["node_modules/demo-package"]["version"] = "1.1.0"
                (root / "package-lock.json").write_text(json.dumps(updated_lock, indent=2) + "\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="lockfile refreshed", stderr="")

            with patch("vulcanary.fixes.subprocess.run", side_effect=run_without_network):
                applied = apply_changes(plan)
                self.assertTrue(applied["branch"].startswith("vulcanary/fixes-"))
                self.assertEqual(self._git(root, "branch", "--show-current"), applied["branch"])
                self.assertEqual(json.loads((root / "package.json").read_text())["dependencies"]["demo-package"], "^1.1.0")
                self.assertEqual(json.loads((root / "package-lock.json").read_text())["packages"]["node_modules/demo-package"]["version"], "1.1.0")
                committed = commit_changes(applied["repository"], applied["branch"])

            self.assertNotEqual(committed["commit"], original_commit)
            self.assertEqual(self._git(root, "status", "--porcelain"), "")
            self.assertEqual(self._git(root, "show", "--format=%s", "--no-patch", "HEAD"), "fix: apply verified Vulcanary dependency upgrades")

    def test_npm_failure_restores_original_branch_and_redacts_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_package = self._initialize_repository(root)
            plan = self._plan(root)
            real_run = subprocess.run

            def fail_npm(command, **kwargs):
                if Path(command[0]).stem.lower() != "npm":
                    return real_run(command, **kwargs)
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="registry token: secret-value")

            with patch("vulcanary.fixes.subprocess.run", side_effect=fail_npm):
                with self.assertRaisesRegex(ValueError, "all changes were rolled back") as raised:
                    apply_changes(plan)

            self.assertNotIn("secret-value", str(raised.exception))
            self.assertEqual(self._git(root, "branch", "--show-current"), "main")
            self.assertNotIn("vulcanary/fixes-", self._git(root, "branch", "--list"))
            self.assertEqual(json.loads((root / "package.json").read_text()), original_package)
            self.assertEqual(self._git(root, "status", "--porcelain"), "")

    def test_project_verification_is_argument_safe_and_redacts_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            passed = run_verification(directory, [[sys.executable, "-c", "print('ok')"]], 10)
            failed = run_verification(
                directory,
                [[sys.executable, "-c", "import sys; print('src/app.ts(12,4): error TS2322: secret-value'); sys.exit(7)"]],
                10,
            )

        self.assertTrue(passed["passed"])
        self.assertEqual(passed["results"][0]["returncode"], 0)
        self.assertFalse(failed["passed"])
        self.assertEqual(failed["results"][0]["returncode"], 7)
        self.assertEqual(failed["diagnostics"], [{"path": "src/app.ts", "line": 12, "column": 4, "code": "TS2322"}])
        self.assertNotIn("secret-value", json.dumps(failed))

    def test_remediation_receipt_is_hashed_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.json"
            applied = {
                "repository": str(Path(directory) / "demo"), "branch": "vulcanary/fixes-demo",
                "files": ["package-lock.json", "package.json"],
                "validation": {"passed": True, "remaining": [], "finding_count": 2},
                "verification": {"passed": True, "skipped": False, "results": [{"command": "check 1 (npm)", "returncode": 0, "diagnostics": []}]},
            }
            receipt = remediation_receipt(applied, ["finding-b", "finding-a"])
            self.assertEqual(len(receipt["proof"]), 64)
            self.assertTrue(remediation_receipt_valid(receipt))
            self.assertFalse(remediation_receipt_valid(dict(receipt, finding_count=3)))
            self.assertEqual(receipt["selected_fingerprints"], ["finding-a", "finding-b"])
            state = DashboardState(history)
            state.record_remediation("verified", receipt)
            restored = DashboardState(history)
            self.assertEqual(restored.remediation_audit[0]["proof"], receipt["proof"])
            self.assertEqual(restored.snapshot()["remediation_audit"][0]["action"], "verified")
            self.assertTrue(restored.snapshot()["remediation_audit"][0]["receipt_valid"])
            failed = remediation_receipt({**applied, "validation": {"passed": False, "remaining": ["finding-a"], "finding_count": 3}, "verification": {"passed": False, "skipped": True, "results": []}}, ["finding-a"])
            self.assertTrue(remediation_receipt_valid(failed))
            self.assertFalse(failed["rescan_passed"])


if __name__ == "__main__":
    unittest.main()
