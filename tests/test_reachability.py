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

    def test_correlates_conservative_import_evidence_across_supported_ecosystems(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {
                "App.java": "import org.apache.logging.log4j.Logger;\n",
                "Program.cs": "using Newtonsoft.Json.Linq;\n",
                "main.go": 'import (\n  "github.com/gin-gonic/gin"\n)\n',
                "lib.rs": "use serde_json::Value;\n",
                "app.rb": "require 'rack/request'\n",
            }
            for name, text in sources.items():
                (root / name).write_text(text, encoding="utf-8")
            findings = [
                dependency("org.apache.logging.log4j:log4j-core", "Maven"),
                dependency("Newtonsoft.Json", "NuGet"),
                dependency("github.com/gin-gonic/gin", "Go"),
                dependency("serde-json", "crates.io"),
                dependency("rack", "RubyGems"),
            ]
            analyzed = analyze_reachability(root, findings, Config())
            self.assertEqual(
                [item.metadata["reachability"]["evidence_paths"] for item in analyzed],
                [["App.java"], ["Program.cs"], ["main.go"], ["lib.rs"], ["app.rb"]],
            )
            self.assertTrue(all(item.metadata["reachability"]["status"] == "direct_import_observed" for item in analyzed))
            self.assertTrue(all(item.metadata["usage"]["classification"] == "direct_application_import_observed" for item in analyzed))

    def test_transitive_ecosystem_match_is_evidence_without_claiming_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "App.java").write_text("import org.apache.logging.log4j.Logger;\n", encoding="utf-8")
            finding = dependency("org.apache.logging.log4j:log4j-core", "Maven", direct=False)
            analyzed = analyze_reachability(root, [finding], Config())[0]
            self.assertEqual(analyzed.metadata["reachability"]["status"], "direct_import_observed")
            self.assertEqual(analyzed.metadata["usage"]["classification"], "dependency_import_observed")
            self.assertIn("does not prove", analyzed.metadata["reachability"]["reason"])

    def test_local_ruby_require_relative_is_not_dependency_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.rb").write_text("require_relative 'rack/request'\n", encoding="utf-8")
            analyzed = analyze_reachability(root, [dependency("rack", "RubyGems")], Config())[0]
            self.assertEqual(analyzed.metadata["reachability"]["status"], "not_observed")

    def test_parent_dotnet_namespace_is_not_treated_as_package_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Program.cs").write_text("using Microsoft.Extensions;\n", encoding="utf-8")
            finding = dependency("Microsoft.Extensions.Logging", "NuGet")
            analyzed = analyze_reachability(root, [finding], Config())[0]
            self.assertEqual(analyzed.metadata["reachability"]["status"], "not_observed")

    def test_unsupported_package_namespace_mapping_remains_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            analyzed = analyze_reachability(
                Path(directory), [dependency("symfony/http-foundation", "Packagist")], Config(),
            )[0]
            self.assertEqual(analyzed.metadata["reachability"]["status"], "unknown")
            self.assertIn("no reliable", analyzed.metadata["reachability"]["reason"])

    def test_import_examples_in_comments_and_multiline_literals_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "App.java").write_text(
                '/*\nimport org.apache.logging.log4j.Logger;\n*/\nString example = """\nimport org.apache.logging.log4j.Logger;\n""";\n',
                encoding="utf-8",
            )
            (root / "lib.rs").write_text(
                '/*\nuse serde_json::Value;\n*/\nlet example = r#"\nuse serde_json::Value;\n"#;\n',
                encoding="utf-8",
            )
            findings = [
                dependency("org.apache.logging.log4j:log4j-core", "Maven"),
                dependency("serde-json", "crates.io"),
            ]
            analyzed = analyze_reachability(root, findings, Config())
            self.assertTrue(all(item.metadata["reachability"]["status"] == "not_observed" for item in analyzed))

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
