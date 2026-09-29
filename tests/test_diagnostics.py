import unittest

from vulcanary.diagnostics import dependency_diagnostics


class DiagnosticTests(unittest.TestCase):
    def test_dependency_warning_shapes_are_actionable_and_additive(self):
        records = dependency_diagnostics([
            "Cargo.lock: dependency input is 35651584 bytes and exceeds the 33554432-byte limit",
            "Gemfile.lock: invalid Bundler dependency input",
            "requirements.txt:requests", "pom.xml: missing resolved dependency tree",
        ], "OSV lookup unavailable")
        self.assertEqual(len(records), 5)
        self.assertEqual(records[0]["code"], "dependency_input_too_large")
        self.assertIn("34.0 MiB", records[0]["message"])
        self.assertEqual(records[0]["limit_bytes"], 33554432)
        self.assertEqual(records[1]["path"], "Gemfile.lock")
        self.assertEqual(records[2]["code"], "dependency_version_unresolved")
        self.assertEqual(records[-1]["code"], "advisory_lookup_unavailable")
        self.assertTrue(all(item["message"] and item["action"] and item["capability"] for item in records))
        self.assertEqual(dependency_diagnostics([]), [])
