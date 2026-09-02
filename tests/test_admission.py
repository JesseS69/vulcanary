import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.admission import load_dependency_policy, review_dependency_changes
from vulcanary.cli import main


def write_lock(root: Path, packages: dict) -> None:
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, **packages}}), encoding="utf-8")


class AdmissionTests(unittest.TestCase):
    def test_blocks_new_denied_scripted_and_unverified_packages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = Path(directory) / "current", Path(directory) / "base"
            root.mkdir(); base.mkdir()
            write_lock(base, {})
            write_lock(root, {"node_modules/bad": {"version": "1.0.0", "license": "GPL-3.0", "hasInstallScript": True, "resolved": "https://registry.npmjs.org/bad/-/bad-1.0.0.tgz"}})
            (base / ".vulcanary.json").write_text(json.dumps({"dependency_policy": {"deny_packages": ["bad"], "deny_licenses": ["GPL-3.0"], "allow_install_scripts": False}}), encoding="utf-8")
            findings, added = review_dependency_changes(root, base)
            self.assertEqual(len(added), 1)
            self.assertEqual({item.rule_id for item in findings}, {"ADMISSION-DENIED-PACKAGE", "ADMISSION-DENIED-LICENSE", "ADMISSION-INSTALL-SCRIPT", "ADMISSION-MISSING-INTEGRITY"})

    def test_unchanged_dependencies_are_not_reblocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = Path(directory) / "current", Path(directory) / "base"
            root.mkdir(); base.mkdir()
            package = {"node_modules/demo": {"version": "1.0.0", "integrity": "sha512-reviewed", "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}}
            write_lock(root, package); write_lock(base, package)
            findings, added = review_dependency_changes(root, base)
            self.assertEqual((findings, added), ([], []))

    def test_policy_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text('{"dependency_policy":{"magic":true}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_dependency_policy(root)

    def test_cli_fails_closed_and_writes_normalized_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = Path(directory) / "current", Path(directory) / "base"
            root.mkdir(); base.mkdir()
            write_lock(base, {})
            write_lock(root, {"node_modules/demo": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"}})
            output = root / "admission.json"
            self.assertEqual(main(["dependency-review", str(root), "--base", str(base), "--json", str(output)]), 1)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["policy"]["mode"], "dependency-admission")
            self.assertEqual(document["findings"][0]["rule_id"], "ADMISSION-MISSING-INTEGRITY")

    def test_candidate_cannot_weaken_trusted_base_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, base = Path(directory) / "current", Path(directory) / "base"
            root.mkdir(); base.mkdir()
            write_lock(base, {})
            write_lock(root, {"node_modules/bad": {"version": "1.0.0", "integrity": "sha512-reviewed"}})
            (base / ".vulcanary.json").write_text('{"dependency_policy":{"deny_packages":["bad"]}}', encoding="utf-8")
            (root / ".vulcanary.json").write_text('{"dependency_policy":{"deny_packages":[]}}', encoding="utf-8")
            findings, _ = review_dependency_changes(root, base)
            self.assertIn("ADMISSION-DENIED-PACKAGE", {item.rule_id for item in findings})
