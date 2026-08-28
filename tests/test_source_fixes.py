from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from vulcanary.source_fixes import apply_source_fix, preview_source_fix


class SourceFixTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
