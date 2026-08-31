from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from vulcanary.source_fixes import apply_source_fix, preview_source_fix


class SourceFixTests(unittest.TestCase):
    def test_disables_persisted_checkout_credentials_in_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("steps:\n  - uses: actions/checkout@sha\n    with:\n      persist-credentials: true\n", encoding="utf-8")
            finding = {
                "repository_path": str(root), "path": ".github/workflows/ci.yml", "line": 4,
                "rule_id": "CI-GHA-PERSIST-CREDENTIALS", "fingerprint": "a" * 20,
            }
            proposal = preview_source_fix(finding)
            self.assertIn("persist-credentials: false", proposal["diff"])
            self.assertEqual(proposal["recipe"], "github-checkout-disable-persisted-credentials")

    def _git(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-c", "user.name=Vulcanary Test", "-c", "user.email=test@example.invalid", "-C", str(root), *args],
            text=True, capture_output=True, check=True,
        )

    def test_static_innerhtml_recipe_previews_and_applies_on_branch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "screen.tsx"
            source.write_text(
                "const update = () => {\n"
                "  el.innerHTML = `<span aria-hidden=\"true\" style=\"font-size: 28px;\">+</span>${showLabel ? '<span>Create</span>' : ''}`;\n"
                "};\n", encoding="utf-8",
            )
            scripts = root / "scripts"
            scripts.mkdir()
            regression = scripts / "beta-regression-checks.js"
            regression.write_text(
                "requireText('screen.tsx', \"showLabel ? '<span>Create</span>' : ''\");\n",
                encoding="utf-8",
            )
            security_tests = root / "tests" / "security"
            security_tests.mkdir(parents=True)
            funnel = security_tests / "onboardingFunnel.test.mjs"
            funnel.write_text(
                "  assert.match(socialFeed, /showLabel \\? '<span>Create<\\/span>' : ''/);\n",
                encoding="utf-8",
            )
            self._git(root, "init", "-b", "main")
            self._git(root, "add", "screen.tsx", "scripts/beta-regression-checks.js", "tests/security/onboardingFunnel.test.mjs")
            self._git(root, "commit", "-m", "initial")
            finding = {
                "rule_id": "CODE-JS-INNERHTML", "repository_path": str(root), "path": "screen.tsx",
                "line": 2, "fingerprint": "source-fingerprint",
            }
            proposal = preview_source_fix(finding)
            self.assertIn("replaceChildren", proposal["diff"])
            self.assertEqual(proposal["files"], ["screen.tsx", "scripts/beta-regression-checks.js", "tests/security/onboardingFunnel.test.mjs"])
            applied = apply_source_fix(proposal)
            self.assertTrue(applied["branch"].startswith("vulcanary/source-fix-"))
            revised = source.read_text(encoding="utf-8")
            self.assertNotIn("innerHTML", revised)
            self.assertIn("textContent = 'Create'", revised)
            self.assertIn("vulcanaryLabel.textContent", regression.read_text(encoding="utf-8"))
            self.assertIn("replaceChildren", funnel.read_text(encoding="utf-8"))

    def test_contextual_innerhtml_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "screen.js").write_text("element.innerHTML = userInput;\n", encoding="utf-8")
            finding = {
                "rule_id": "CODE-JS-INNERHTML", "repository_path": str(root), "path": "screen.js",
                "line": 1, "fingerprint": "dynamic",
            }
            with self.assertRaisesRegex(ValueError, "contextual review"):
                preview_source_fix(finding)

    def test_python_eval_recipe_adds_ast_import_and_applies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "parser.py"
            source.write_text('"""Literal settings parser."""\nfrom __future__ import annotations\n\ndef parse(value):\n    return eval(value)\n', encoding="utf-8")
            self._git(root, "init", "-b", "main")
            self._git(root, "add", "parser.py")
            self._git(root, "commit", "-m", "initial")
            finding = {
                "rule_id": "CODE-PY-EVAL", "repository_path": str(root), "path": "parser.py",
                "line": 5, "fingerprint": "python-eval-fingerprint",
            }
            proposal = preview_source_fix(finding)
            self.assertEqual(proposal["recipe"], "python-eval-to-literal-eval")
            self.assertIn("import ast", proposal["diff"])
            self.assertIn("ast.literal_eval(value)", proposal["diff"])
            apply_source_fix(proposal)
            revised = source.read_text(encoding="utf-8")
            self.assertLess(revised.index("from __future__ import annotations"), revised.index("import ast"))
            self.assertIn("return ast.literal_eval(value)", revised)

    def test_python_eval_recipe_refuses_executable_expression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "parser.py").write_text("result = eval(build_expression())\n", encoding="utf-8")
            finding = {
                "rule_id": "CODE-PY-EVAL", "repository_path": str(root), "path": "parser.py",
                "line": 1, "fingerprint": "dynamic-python-eval",
            }
            with self.assertRaisesRegex(ValueError, "contextual review"):
                preview_source_fix(finding)

    def test_python_shell_recipe_removes_shell_for_static_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "runner.py"
            source.write_text("import subprocess\n\ndef status():\n    return subprocess.run(['git', 'status', '--short'], check=True, shell=True)\n", encoding="utf-8")
            self._git(root, "init", "-b", "main")
            self._git(root, "add", "runner.py")
            self._git(root, "commit", "-m", "initial")
            finding = {
                "rule_id": "CODE-PY-SHELL", "repository_path": str(root), "path": "runner.py",
                "line": 4, "fingerprint": "python-shell-fingerprint",
            }
            proposal = preview_source_fix(finding)
            self.assertEqual(proposal["recipe"], "python-static-argv-without-shell")
            self.assertIn("-    return subprocess.run", proposal["diff"])
            apply_source_fix(proposal)
            revised = source.read_text(encoding="utf-8")
            self.assertIn("subprocess.run(['git', 'status', '--short'], check=True)", revised)
            self.assertNotIn("shell=True", revised)

    def test_python_shell_recipe_refuses_string_or_dynamic_argv(self) -> None:
        for command in ("'git status'", "command", "['git', user_arg]"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "runner.py").write_text(f"subprocess.run({command}, shell=True)\n", encoding="utf-8")
                finding = {
                    "rule_id": "CODE-PY-SHELL", "repository_path": str(root), "path": "runner.py",
                    "line": 1, "fingerprint": "dynamic-python-shell",
                }
                with self.assertRaisesRegex(ValueError, "contextual review"):
                    preview_source_fix(finding)


if __name__ == "__main__":
    unittest.main()
