"""Required CI suite; missing jsonschema is an error, never a skipped check."""
import copy
import hashlib
import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from fixtures import reports
from vulcanary.dataflow import analyze_python_dataflow

ROOT = Path(__file__).parent


def refuse_remote(uri):
    raise NoSuchResource(ref=uri)


def validator(name):
    registry = Registry(retrieve=refuse_remote)
    for path in (ROOT / "upstream").glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        identifier = schema.get("$id", schema.get("id"))
        registry = registry.with_resource(identifier, Resource.from_contents(schema))
    folder = "upstream" if name in {"sarif", "cyclonedx", "spdx", "openvex"} else "schemas"
    schema = json.loads((ROOT / folder / f"{name}.json").read_text(encoding="utf-8"))
    cls = validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, registry=registry, format_checker=FormatChecker())


class SchemaContracts(unittest.TestCase):
    def test_nonempty_experimental_gaps_and_limits_validate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def deep():\n    return request.args.get('q')\n"
                "def wrapper():\n    return deep()\n"
                "eval(wrapper())\neval(external())\n", encoding="utf-8")
            report = analyze_python_dataflow(root, max_depth=1)
            self.assertTrue(report["unmodeled_constructs"])
            self.assertTrue(report["warnings"])
            self.assertTrue(report["analysis_truncations"])
            validator("experimental-dataflow").validate(report)
            broken = copy.deepcopy(report)
            del broken["warnings"][0]["action"]
            self.assertFalse(validator("experimental-dataflow").is_valid(broken))
            report = analyze_python_dataflow(root, max_calls=1)
            self.assertTrue(report["analysis_limits"])
            validator("experimental-dataflow").validate(report)

    def test_generated_and_golden_documents_validate_offline(self):
        with patch("socket.socket", side_effect=AssertionError("Contract validation must be offline")):
            for empty in (False, True):
                for name, document in reports(empty).items():
                    with self.subTest(format=name, empty=empty):
                        validator(name).validate(document)
            for path in (ROOT / "golden").glob("*.json"):
                with self.subTest(golden=path.name):
                    validator(path.stem).validate(json.loads(path.read_text(encoding="utf-8")))

    def test_upstream_schema_bytes_match_pins(self):
        manifest = json.loads((ROOT / "upstream-sources.json").read_text(encoding="utf-8"))
        for entry in manifest:
            self.assertEqual(hashlib.sha256((ROOT / "upstream" / entry["file"]).read_bytes()).hexdigest(), entry["sha256"])

    def test_breaking_mutations_are_rejected(self):
        documents = reports()
        mutations = {
            "normalized": lambda d: d["findings"][0].update(severity="extreme"),
            "sarif": lambda d: d["runs"][0]["results"][0].update(level="high"),
            "cyclonedx": lambda d: d["vulnerabilities"][0]["ratings"][0].update(severity="extreme"),
            "spdx": lambda d: d["packages"][0].update(filesAnalyzed="false"),
            "openvex": lambda d: d["statements"][0].pop("action_statement"),
            "ruleset": lambda d: d.update(version="1"),
            "receipt": lambda d: d.update(checks_passed="true"),
            "experimental-dataflow": lambda d: d.update(policy_effect="gating"),
        }
        for name, mutate in mutations.items():
            with self.subTest(format=name):
                document = copy.deepcopy(documents[name])
                mutate(document)
                self.assertTrue(list(validator(name).iter_errors(document)))

    def test_format_and_external_reference_validation_are_active(self):
        document = reports()["openvex"]
        document["timestamp"] = "not-a-date"
        self.assertTrue(list(validator("openvex").iter_errors(document)))
        document = reports()["cyclonedx"]
        document["components"][0]["licenses"] = [{"license": {"id": "NOT-A-LICENSE"}}]
        self.assertTrue(list(validator("cyclonedx").iter_errors(document)))


if __name__ == "__main__":
    unittest.main()
