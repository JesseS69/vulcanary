from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from vulcanary.adapters import AdapterError, PARSERS, import_document, import_report
from vulcanary.config import Config
from vulcanary.dashboard import _coverage_matrix
from vulcanary.dataflow import analyze_python_dataflow
from vulcanary.dependencies import discover_dependency_state


_MANIFEST_SEEDS = {
    "package-lock.json": '{"packages":{"":{"dependencies":{"demo":"1"}},"node_modules/demo":{"version":"1.0.0"}}}',
    "package.json": '{"dependencies":{"demo":"1"}}',
    "yarn.lock": 'demo@^1:\n  version "1.0.0"\n',
    "pnpm-lock.yaml": "packages:\n  demo@1.0.0:\n",
    "poetry.lock": '[[package]]\nname = "demo"\nversion = "1.0.0"\n',
    "uv.lock": '[[package]]\nname = "demo"\nversion = "1.0.0"\n',
    "pdm.lock": '[[package]]\nname = "demo"\nversion = "1.0.0"\n',
    "Cargo.lock": '[[package]]\nname = "demo"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
    "Cargo.toml": '[dependencies]\ndemo = "1"\n',
    "go.mod": "module example.test/demo\nrequire example.test/library v1.2.3\n",
    "composer.lock": '{"packages":[{"name":"vendor/demo","version":"1.0.0"}]}',
    "composer.json": '{"require":{"vendor/demo":"1.0.0"}}',
    "packages.lock.json": '{"dependencies":{"net8.0":{"Demo":{"type":"Direct","resolved":"1.0.0"}}}}',
    "maven-dependency-tree.json": '{"children":[{"groupId":"test","artifactId":"demo","version":"1.0.0"}]}',
    "gradle.lockfile": "test:demo:1.0.0=runtimeClasspath\n",
    "Gemfile.lock": "GEM\n  specs:\n    demo (1.0.0)\n\nDEPENDENCIES\n  demo\n",
    "Pipfile.lock": '{"default":{"demo":{"version":"==1.0.0"}}}',
    "requirements.txt": "demo==1.0.0\n",
    "bom.json": '{"bomFormat":"CycloneDX","components":[{"purl":"pkg:npm/demo@1.0.0"}]}',
}

_ADAPTER_SEEDS = {
    "semgrep": {"results": [{"check_id": "R", "path": "app.py", "start": {"line": 1}, "extra": {"message": "demo", "severity": "LOW", "metadata": {}}}]},
    "gitleaks": [{"RuleID": "R", "Description": "demo", "File": "app.env", "StartLine": 1}],
    "trivy": {"SchemaVersion": 2, "Results": [{"Target": "lock", "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}], "Misconfigurations": [{"ID": "CFG-1"}]}]},
    "trivy-image": {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}]},
    "checkov": {"results": {"failed_checks": [{"check_id": "R", "file_line_range": [1]}]}},
    "zap": {"site": [{"@host": "example.test", "alerts": [{"pluginid": "1", "instances": [{"uri": "https://example.test"}]}]}]},
    "sarif": {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "demo", "rules": [{"id": "R"}]}}, "results": [{"ruleId": "R", "message": {"text": "demo"}, "locations": []}]}]},
    "prowler": [{"status": "FAIL", "finding_info": {"uid": "R", "title": "demo"}, "resources": [], "metadata": {}, "remediation": {}}],
}


def _mutations(seed: str) -> list[bytes]:
    """Fixed-seed mutations: reproducible failures can be promoted to regression seeds."""
    source = seed.encode("utf-8")
    cases = [b"", b"\x00\xff\xfe", source[: max(1, len(source) // 2)], source + b"\x00"]
    rng = random.Random(0x56_1CA)
    for _ in range(8):
        candidate = bytearray(source)
        if candidate:
            for _ in range(1 + rng.randrange(4)):
                index = rng.randrange(len(candidate))
                candidate[index] = rng.randrange(256)
        cases.append(bytes(candidate))
    return cases


def _shape_mutations(document: object) -> list[object]:
    """Replace each nested field with hostile JSON-compatible types, deterministically."""
    cases: list[object] = []

    def visit(value: object, path: tuple[object, ...]) -> None:
        if path:
            for replacement in (None, False, 7, "unexpected", [], {}):
                clone = json.loads(json.dumps(document))
                target = clone
                for part in path[:-1]:
                    target = target[part]  # type: ignore[index]
                target[path[-1]] = replacement  # type: ignore[index]
                cases.append(clone)
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, path + (key,))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + (index,))

    visit(document, ())
    return cases


class ParserRobustnessTests(unittest.TestCase):
    def test_recognized_malformed_manifests_emit_incomplete_analysis_signals(self) -> None:
        filenames = (
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "pdm.lock",
            "Cargo.lock", "go.mod", "composer.lock", "packages.lock.json", "gradle.lockfile",
            "Gemfile.lock", "Pipfile.lock", "requirements.txt",
        )
        for filename in filenames:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_bytes(b"\xff\xfe")
                packages, warnings = discover_dependency_state(root)
                self.assertEqual(packages, [])
                self.assertTrue(warnings, f"{filename} was silently skipped")
                self.assertTrue(any(filename.lower() in warning.lower() for warning in warnings))

    def test_structurally_invalid_json_locks_emit_incomplete_analysis_signals(self) -> None:
        for filename in ("package-lock.json", "composer.lock", "packages.lock.json", "Pipfile.lock"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_text("{}", encoding="utf-8")
                packages, warnings = discover_dependency_state(root)
                self.assertEqual(packages, [])
                self.assertTrue(warnings, f"{filename} had no schema warning")

    def test_malformed_manifest_signals_feed_machine_readable_coverage_gaps(self) -> None:
        cases = {
            "package-lock.json": "npm", "Pipfile.lock": "Python", "Cargo.lock": "Cargo",
            "go.mod": "Go", "composer.lock": "Composer", "packages.lock.json": "NuGet",
            "gradle.lockfile": "Maven / Gradle", "Gemfile.lock": "RubyGems",
        }
        for filename, ecosystem in cases.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_bytes(b"\xff\xfe")
                packages, warnings = discover_dependency_state(root)
                rows = _coverage_matrix(root, packages, warnings, False, Config())
                row = next(item for item in rows if item["ecosystem"] == ecosystem)
                self.assertEqual(row["dependency"], "gap")
                self.assertIn(filename, row["detail"])

    def test_dependency_manifests_with_unresolved_dependencies_emit_signals(self) -> None:
        cases = {
            "package.json": '{"dependencies":{"demo":"^1"}}',
            "Cargo.toml": '[dependencies]\ndemo = "1"\n',
            "composer.json": '{"require":{"vendor/demo":"^1"}}',
            "Gemfile": 'gem "demo", "~> 1"\n',
        }
        for filename, content in cases.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_text(content, encoding="utf-8")
                packages, warnings = discover_dependency_state(root)
                self.assertEqual(packages, [])
                self.assertTrue(any("missing" in warning for warning in warnings))

    def test_empty_manifests_do_not_manufacture_coverage_gaps(self) -> None:
        cases = {
            "package.json": "{}",
            "Cargo.toml": '[package]\nname = "demo"\nversion = "1.0.0"\n',
            "composer.json": "{}",
            "Gemfile": 'source "https://rubygems.org"\n',
        }
        for filename, content in cases.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_text(content, encoding="utf-8")
                packages, warnings = discover_dependency_state(root)
                self.assertEqual(packages, [])
                self.assertEqual(warnings, [])

    def test_dependency_discovery_survives_deterministic_manifest_mutations(self) -> None:
        for filename, seed in _MANIFEST_SEEDS.items():
            for case_number, payload in enumerate(_mutations(seed)):
                with self.subTest(filename=filename, case=case_number), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / filename).write_bytes(payload)
                    packages, warnings = discover_dependency_state(root)
                    self.assertIsInstance(packages, list)
                    self.assertIsInstance(warnings, list)

    def test_dependency_discovery_survives_nested_json_manifest_mutations(self) -> None:
        json_seeds = {
            name: json.loads(seed)
            for name, seed in _MANIFEST_SEEDS.items()
            if name.endswith(".json")
        }
        for filename, seed in json_seeds.items():
            for case_number, document in enumerate(_shape_mutations(seed)):
                with self.subTest(filename=filename, case=case_number), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / filename).write_text(json.dumps(document), encoding="utf-8")
                    packages, warnings = discover_dependency_state(root)
                    self.assertIsInstance(packages, list)
                    self.assertIsInstance(warnings, list)

    def test_external_adapters_fail_with_typed_errors_for_malformed_shapes(self) -> None:
        malformed = [None, True, 7, "text", [], {}, {"results": None}, [None], {"runs": [None]}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for scanner in PARSERS:
                for case_number, document in enumerate(malformed):
                    with self.subTest(scanner=scanner, case=case_number):
                        try:
                            findings = import_document(scanner, document, root)
                        except AdapterError:
                            continue
                        self.assertIsInstance(findings, list)

    def test_external_adapters_survive_nested_schema_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for scanner, seed in _ADAPTER_SEEDS.items():
                for case_number, document in enumerate(_shape_mutations(seed)):
                    with self.subTest(scanner=scanner, case=case_number):
                        try:
                            findings = import_document(scanner, document, root)
                        except AdapterError:
                            continue
                        self.assertIsInstance(findings, list)

    def test_external_report_reader_rejects_invalid_utf8_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            for payload in (b"\xff\xfe", b"{", b"null"):
                report.write_bytes(payload)
                with self.assertRaises(AdapterError):
                    import_report("semgrep", report, root)

    def test_python_analysis_survives_deterministic_source_mutations(self) -> None:
        seed = "def handler():\n    value = request.args.get('value')\n    eval(value)\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            for payload in _mutations(seed):
                source.write_bytes(payload)
                report = analyze_python_dataflow(root, timeout_seconds=5)
                self.assertEqual(report["schema"], "vulcanary.experimental-dataflow.v1")
                self.assertEqual(report["policy_effect"], "none")
                self.assertGreaterEqual(report["parse_errors"], 0)


if __name__ == "__main__":
    unittest.main()
