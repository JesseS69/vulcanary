import tempfile
import unittest
from pathlib import Path

from vulcanary.config import Config
from vulcanary.models import Finding, Severity
from vulcanary.reachability import analyze_reachability, observed_imports


def dependency(package: str, ecosystem: str = "npm", direct: bool = True, parents: list[str] | None = None) -> Finding:
    return Finding(
        "SCA-test", f"Vulnerable {package}", "test", Severity.HIGH, "dependency", "lockfile", 1,
        metadata={"package": package, "ecosystem": ecosystem, "direct": direct, "parent_packages": parents or []},
    )


class ReachabilityTests(unittest.TestCase):
    def test_collects_static_javascript_and_python_imports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.ts").write_text("import x from '@scope/tool/client'; const y = require('lodash/map');\n", encoding="utf-8")
            (root / "worker.py").write_text("from requests.sessions import Session\nimport yaml as parser\n", encoding="utf-8")
            npm, python = observed_imports(root, Config())
            self.assertEqual(set(npm), {"@scope/tool", "lodash"})
            self.assertEqual(set(python), {"requests", "yaml"})

    def test_marks_direct_and_parent_import_evidence_without_hiding_absence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.js").write_text("import express from 'express';\n", encoding="utf-8")
            findings = [
                dependency("express"),
                dependency("transitive-demo", direct=False, parents=["express"]),
                dependency("unused-demo"),
            ]
            analyzed = analyze_reachability(root, findings, Config())
            reachability = [item.metadata["reachability"] for item in analyzed]
            self.assertEqual(reachability[0]["status"], "direct_import_observed")
            self.assertEqual(reachability[1]["status"], "parent_import_observed")
            self.assertEqual(reachability[1]["matched_packages"], ["express"])
            self.assertEqual(reachability[2]["status"], "not_observed")
            self.assertIn("may still be reachable", reachability[2]["reason"])


if __name__ == "__main__":
    unittest.main()
