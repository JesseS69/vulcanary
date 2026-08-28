import tempfile
import unittest
from pathlib import Path

from vulcanary.config import Config
from vulcanary.models import Finding, Severity
from vulcanary.reachability import analyze_reachability, observed_imports


def dependency(package: str, ecosystem: str = "npm", direct: bool = True, parents: list[str] | None = None, scopes: dict[str, str] | None = None) -> Finding:
    return Finding(
        "SCA-test", f"Vulnerable {package}", "test", Severity.HIGH, "dependency", "lockfile", 1,
        metadata={"package": package, "ecosystem": ecosystem, "direct": direct, "parent_packages": parents or [], "parent_scopes": scopes or {}, "fixed_version": "2.0.0"},
    )


class ReachabilityTests(unittest.TestCase):
    def test_scores_non_dependency_source_findings(self) -> None:
        finding = Finding(
            "CODE-test", "Unsafe source", "test", Severity.HIGH, "code", "app.py", 1,
            remediation="Replace the unsafe operation.",
        )
        analyzed = analyze_reachability(Path("."), [finding], Config())[0]
        self.assertEqual(analyzed.metadata["usage"]["classification"], "source_observed")
        self.assertEqual(analyzed.metadata["priority"]["level"], "urgent")
        self.assertEqual(analyzed.metadata["recommendation"]["action"], "review_source_fix")

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
                dependency("transitive-demo", direct=False, parents=["express"], scopes={"express": "runtime"}),
                dependency("unused-demo"),
            ]
            analyzed = analyze_reachability(root, findings, Config())
            reachability = [item.metadata["reachability"] for item in analyzed]
            self.assertEqual(reachability[0]["status"], "direct_import_observed")
            self.assertEqual(reachability[1]["status"], "parent_import_observed")
            self.assertEqual(reachability[1]["matched_packages"], ["express"])
            self.assertEqual(analyzed[1].metadata["usage"]["classification"], "runtime_parent_observed")
            self.assertEqual(analyzed[1].metadata["recommendation"]["action"], "evaluate_parent_upgrade")
            self.assertEqual(analyzed[0].metadata["priority"]["level"], "urgent")
            self.assertEqual(analyzed[1].metadata["priority"]["level"], "high_priority")
            self.assertEqual(reachability[2]["status"], "not_observed")
            self.assertIn("may still be reachable", reachability[2]["reason"])

    def test_distinguishes_tooling_chain_from_production_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.js").write_text("import ReactNative from 'react-native';\n", encoding="utf-8")
            finding = dependency("js-yaml", direct=False, parents=["react-native"], scopes={"react-native": "runtime"})
            finding = Finding(**{**finding.__dict__, "metadata": {**finding.metadata, "dependency_paths": [["react-native@1.0.0", "babel-jest@29.0.0", "js-yaml@3.0.0"]]}})
            analyzed = analyze_reachability(root, [finding], Config())[0]
            self.assertEqual(analyzed.metadata["usage"]["classification"], "tooling_path_via_runtime_parent")
            self.assertIn("production execution is not established", analyzed.metadata["usage"]["reason"])
            self.assertEqual(analyzed.metadata["priority"]["level"], "planned")
            self.assertEqual(analyzed.metadata["priority"]["score"], 45)
            self.assertIn("Severity remains unchanged", analyzed.metadata["priority"]["reason"])

    def test_correlates_route_and_deploy_evidence_without_claiming_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            route = root / "app" / "api" / "users"
            route.mkdir(parents=True)
            (route / "route.ts").write_text("import express from 'express';\n", encoding="utf-8")
            (root / "vercel.json").write_text("{}\n", encoding="utf-8")
            analyzed = analyze_reachability(root, [dependency("express")], Config())[0]
            exposure = analyzed.metadata["exposure"]
            self.assertEqual(exposure["classification"], "route_candidate_with_deploy_config")
            self.assertEqual(exposure["route_paths"], ["app/api/users/route.ts"])
            self.assertEqual(exposure["deployment_assets"], ["vercel.json"])
            self.assertIn("does not prove", exposure["reason"])

    def test_missing_exposure_evidence_never_claims_safety(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            analyzed = analyze_reachability(Path(directory), [dependency("unseen")], Config())[0]
            self.assertEqual(analyzed.metadata["exposure"]["classification"], "unknown")
            self.assertIn("not evidence", analyzed.metadata["exposure"]["reason"])


if __name__ == "__main__":
    unittest.main()
