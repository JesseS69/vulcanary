from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary.adapters import AdapterError, import_report
from vulcanary.config import Config
from vulcanary.dashboard import _coverage_matrix
from vulcanary.dataflow import analyze_python_dataflow
from vulcanary.dependencies import discover_dependency_state


class InputLimitTests(unittest.TestCase):
    def test_external_report_over_limit_fails_with_typed_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "semgrep.json"
            report.write_text('{"results": []}', encoding="utf-8")
            with patch("vulcanary.adapters.MAX_REPORT_BYTES", 8):
                with self.assertRaisesRegex(AdapterError, "exceeds the 8-byte input limit"):
                    import_report("semgrep", report, root)

    def test_oversized_dependency_input_is_an_explicit_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "package-lock.json"
            lock.write_text('{"packages": {}}', encoding="utf-8")
            with patch("vulcanary.dependencies.MAX_DEPENDENCY_INPUT_BYTES", 8):
                packages, warnings = discover_dependency_state(root)
            coverage = _coverage_matrix(root, packages, warnings, False, Config(max_file_bytes=8))
        self.assertEqual(packages, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("package-lock.json: dependency input is 16 bytes", warnings[0])
        self.assertIn("exceeds the 8-byte limit", warnings[0])
        self.assertEqual(coverage[0]["ecosystem"], "npm")
        self.assertEqual(coverage[0]["dependency"], "gap")
        self.assertIn("exceeds", coverage[0]["detail"])

    def test_oversized_python_source_is_a_dataflow_limit_not_a_clean_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text(json.dumps({"max_file_bytes": 8}), encoding="utf-8")
            source = b"eval(request.args.get('value'))\n"
            (root / "app.py").write_bytes(source)
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["analyzed_modules"], 0)
        self.assertEqual(report["analysis_limits"], [{
            "category": "source_size_limit", "limit": 8, "observed": len(source), "path": "app.py",
        }])

    def test_repository_cannot_raise_source_limit_without_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text(json.dumps({"max_file_bytes": 10**12}), encoding="utf-8")
            config = Config.load(root)
        self.assertEqual(config.max_file_bytes, 10_000_000)

    def test_repository_configuration_has_an_independent_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text('{"fail_on": "high"}', encoding="utf-8")
            with patch("vulcanary.config.MAX_CONFIG_BYTES", 8):
                with self.assertRaisesRegex(ValueError, "configuration exceeds the 8-byte input limit"):
                    Config.load(root)

    def test_deeply_nested_json_fails_through_public_contracts(self) -> None:
        nested = "[" * 100_000 + "0" + "]" * 100_000
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "semgrep.json"
            report.write_text(nested, encoding="utf-8")
            with self.assertRaisesRegex(AdapterError, "not readable JSON"):
                import_report("semgrep", report, root)

            lock = root / "package-lock.json"
            lock.write_text(nested, encoding="utf-8")
            packages, warnings = discover_dependency_state(root)
            self.assertEqual(packages, [])

            config_path = root / ".vulcanary.json"
            config_path.write_text(nested, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "nesting is too deep"):
                Config.load(root)


if __name__ == "__main__":
    unittest.main()
