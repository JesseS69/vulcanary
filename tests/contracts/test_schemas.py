"""Required CI suite; missing jsonschema is an error, never a skipped check."""
import copy
import io
from contextlib import redirect_stderr
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
from vulcanary.cli_errors import ERRORS, JSON_ERRORS, fail

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
    def test_apk_signature_report_requires_completed_checks_before_pass(self):
        from vulcanary import apk_signatures as signatures
        blocked = signatures.verify(Path('/unavailable'), '', Path('/unavailable'), '', Path('/unavailable'), '', android_api=36)
        contract = validator('apk-signatures')
        contract.validate(blocked)
        self.assertFalse(contract.is_valid({**blocked, 'state': 'PASS'}))
        self.assertFalse(contract.is_valid({**blocked, 'stdout': 'private'}))
        passed = {**blocked, 'state': 'PASS', 'attempted': True, 'cleanup': 'complete',
                  'android_api': 36, 'size_bytes': 5000, 'tool_version': '0.9', 'timeout_seconds': 30,
                  'artifact_sha256': 'a'*64, 'java_sha256': 'b'*64, 'verifier_sha256': 'c'*64,
                  'expected_cert_sha256': 'd'*64, 'signer_cert_sha256': 'd'*64, 'warning_count': 0,
                  'schemes': {'v1': False, 'v2': False, 'v3': True, 'v3.1': False, 'v4': False},
                  'checks': [{**r, 'state': 'PASS'} for r in blocked['checks']],
                  'counts': {'PASS': 3, 'FAIL': 0, 'BLOCKED': 0}}
        contract.validate(passed)
        for changes in ({'cleanup': 'unconfirmed'}, {'warning_count': 1}, {'expected_cert_sha256': None},
                        {'application_executed': True}):
            self.assertFalse(contract.is_valid({**passed, **changes}))

    def test_apk_collection_contract_forbids_false_pass_and_partial_artifact_claims(self):
        from vulcanary import android_apk_collection as collector
        report = collector.collect('synthetic', 'org.example.app', {}, Path('unused'))
        contract = validator('android-apk-collection')
        contract.validate(report)
        for changes in ({'state': 'PASS'}, {'raw_path': '/data/private'}, {'application_executed': True},
                        {'collection_state': 'COMPLETE'}):
            self.assertFalse(contract.is_valid({**report, **changes}))
        complete = {**report, 'state': 'NOT_RUN', 'collection_state': 'COMPLETE',
                    'reason': 'apk_bytes_collected_security_not_run',
                    'expected_inventory_sha256': 'a'*64, 'device_selector_sha256': 'b'*64, 'application_id_sha256': 'c'*64,
                    'artifacts': [{'id': 'artifact-000', 'role': 'base', 'device_path_sha256': 'd'*64, 'sha256': 'e'*64, 'size_bytes': 40}],
                    'observations': {'android_release': '15', 'android_api': 35, 'model_sha256': 'f'*64,
                                     'version_code': 31, 'apk_path_count': 1, 'apk_path_sha256': ['d'*64], 'matching_package_snapshots': True}}
        contract.validate(complete)
        for changes in ({'cleanup_complete': False}, {'artifacts': []}, {'observations': None}, {'state': 'PASS'}):
            self.assertFalse(contract.is_valid({**complete, **changes}))
        self.assertFalse(contract.is_valid({**report, 'artifacts': complete['artifacts']}))

    def test_android_inventory_never_claims_security_pass_or_raw_evidence(self):
        from vulcanary import android_inventory as inventory
        blocked = inventory.inspect('synthetic-device', 'org.example.app')
        contract = validator('android-inventory')
        contract.validate(blocked)
        observed = {'android_release': '15', 'android_api': 35, 'model_sha256': 'a' * 64,
                    'version_code': 31, 'apk_path_count': 1, 'apk_path_sha256': ['b' * 64],
                    'matching_package_snapshots': True}
        with patch.object(inventory, 'collect', return_value=b''), patch.object(inventory, 'parse', return_value=observed):
            completed = inventory.inspect('synthetic-device', 'org.example.app', authorized=True, trust_existing_server=True)
        contract.validate(completed)
        for changes in ({'state': 'PASS'}, {'stdout': 'private'}, {'application_executed': True},
                        {'observations': None}, {'device_selector_sha256': None}):
            self.assertFalse(contract.is_valid({**completed, **changes}))
        self.assertFalse(contract.is_valid({**blocked, 'observations': observed}))

    def test_local_test_report_refuses_false_pass_and_raw_output(self):
        import sys
        from vulcanary.local_tests import execute
        python = Path(sys.executable).resolve()
        pin = hashlib.sha256(python.read_bytes()).hexdigest()
        version = '.'.join(map(str, sys.version_info[:3]))
        with tempfile.TemporaryDirectory() as directory:
            spec = Path(directory) / 'vectors.json'
            for expected in (hashlib.sha256(b'').hexdigest(), '0' * 64):
                spec.write_text(json.dumps({'cases': [{'input_hex': '', 'expected_sha256': expected}]}))
                report = execute(spec, python, pin, version, authorized=True)
                self.assertIn(report['state'], ('PASS', 'FAIL'))
                validator('local-test-run').validate(report)
                self.assertFalse(validator('local-test-run').is_valid({**report, 'stdout': 'secret'}))
                self.assertFalse(validator('local-test-run').is_valid({**report, 'executed': False}))
            blocked = execute(spec, python, pin, version)
            validator('local-test-run').validate(blocked)
            self.assertFalse(validator('local-test-run').is_valid({**blocked, 'state': 'PASS'}))

    def test_security_run_contract_refuses_false_pass_and_raw_evidence(self):
        from vulcanary.security_testing import register, execute
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = root / "spec.json"
            spec.write_text(json.dumps({"files": ["eval(user_input)\n"], "checks": [
                {"method": "automated", "rule": "CODE-PY-EVAL", "expected_count": 0},
                {"method": "manual", "kind": "device-privacy"}]}))
            register(spec, root / "target.json", authorized=True)
            report = execute(root / "target.json")
            validator("security-test-run").validate(report)
            broken = copy.deepcopy(report)
            broken["checks"][1]["state"] = "PASS"
            self.assertFalse(validator("security-test-run").is_valid(broken))
            broken = copy.deepcopy(report)
            broken["evidence"][0]["source"] = "secret"
            self.assertFalse(validator("security-test-run").is_valid(broken))
            validator("security-test-run").validate(execute(root / "missing.json"))

    def test_cli_errors_validate_and_reject_breaking_changes(self):
        token = JSON_ERRORS.set(True)
        try:
            for code in ERRORS:
                output = io.StringIO()
                with redirect_stderr(output):
                    fail(code)
                document = json.loads(output.getvalue())
                validator("cli-error").validate(document)
                for key, value in (("exit_code", "2"), ("code", "new_code"), ("action", "")):
                    self.assertFalse(validator("cli-error").is_valid({**document, key: value}))
        finally:
            JSON_ERRORS.reset(token)

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
