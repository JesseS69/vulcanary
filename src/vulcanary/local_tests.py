"""Opt-in trusted Python execution over bounded synthetic test vectors."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone

from .cli_errors import ArgumentParser
from .security_testing import digest, read_document, write_new
from ._test_process import OUTPUT_LIMIT_BYTES, run_worker
from .version import __version__

HASH = re.compile(r"[a-f0-9]{64}\Z")


def validate(spec):
    if set(spec) != {"cases"} or not isinstance(spec["cases"], list) or not 1 <= len(spec["cases"]) <= 64:
        raise ValueError("invalid_vectors")
    for case in spec["cases"]:
        if not isinstance(case, dict) or set(case) != {"input_hex", "expected_sha256"}:
            raise ValueError("invalid_vectors")
        value, expected = case["input_hex"], case["expected_sha256"]
        if not isinstance(value, str) or len(value) > 8192 or len(value) % 2 or not re.fullmatch(r"[0-9a-f]*", value):
            raise ValueError("invalid_vectors")
        if not isinstance(expected, str) or not HASH.fullmatch(expected):
            raise ValueError("invalid_vectors")


def execute(spec_path, python, tool_sha256, python_version, *, authorized=False, timeout=10.0):
    report = {"schema": "vulcanary.local-test-run.v1", "adapter": "python-sha256-unittest.v1",
              "producer_version": __version__, "run_id": str(uuid.uuid4()),
              "started_at": datetime.now(timezone.utc).isoformat(), "state": "BLOCKED",
              "attempted": False, "executed": False, "policy_effect": "none",
              "independent_certification": False, "target_sha256": None,
              "scope": "trusted-local-synthetic-vectors", "plan_sha256": None,
              "implementation_sha256": digest({name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                                for name in ("local_tests.py", "_test_process.py", "_vector_worker.py")}),
              "tool_sha256": None, "python_version": None, "worker_sha256": None,
              "expected_tests": None, "observed": None, "cleanup": "not_needed",
              "reason": "authorization_required", "timeout_seconds": None,
              "output_limit_bytes": OUTPUT_LIMIT_BYTES,
              "limitations": ["Bundled synthetic SHA-256 vectors only; no application test suites.",
                              "Trusted interpreter and installation required; executable hash does not pin its libraries.",
                              "Not a filesystem or network sandbox. No endpoint or device is configured.",
                              "Implementation assertions, not cryptographic design assurance or certification.",
                              "No raw stdout, stderr, exceptions, source or vector values are exported."]}
    try:
        if not authorized:
            return report
        if type(timeout) not in (int, float) or not 0.05 <= timeout <= 30:
            report["reason"] = "invalid_timeout"
            return report
        report["timeout_seconds"] = timeout
        report["reason"] = "invalid_vectors"
        spec = read_document(spec_path)
        validate(spec)
        report.update(target_sha256=digest([case["input_hex"] for case in spec["cases"]]),
                      plan_sha256=digest(spec), expected_tests=len(spec["cases"]))
        report["reason"] = "tool_unavailable_or_untrusted"
        if not python.is_absolute() or not python.is_file() or not HASH.fullmatch(tool_sha256):
            return report
        with python.open("rb") as stream:
            tool = stream.read(64 * 1024 * 1024 + 1)
        if len(tool) > 64 * 1024 * 1024 or hashlib.sha256(tool).hexdigest() != tool_sha256:
            return report
        if not re.fullmatch(r"\d+\.\d+\.\d+", python_version):
            return report
        report["tool_sha256"] = tool_sha256
        worker = Path(__file__).with_name("_vector_worker.py").read_bytes()
        report["worker_sha256"] = hashlib.sha256(worker).hexdigest()
        report["reason"] = "execution_or_cleanup_failed"
        report["cleanup"] = "unconfirmed"
        # No caller-selected working directory, script, arguments or environment.
        with tempfile.TemporaryDirectory(prefix="vulcanary-local-test-") as folder:
            root = Path(folder)
            (root / "worker.py").write_bytes(worker)
            write_new(root / "vectors.json", spec)
            report["attempted"] = True
            code, raw, reason = run_worker([str(python), "-I", "-S", str(root / "worker.py")], root, timeout)
        report["cleanup"] = "complete"
        # A controller refusal takes precedence over any child-reported exit code.
        if reason:
            report["reason"] = reason
            return report
        if code != 0:
            report["reason"] = "worker_crash"
            return report
        report["reason"] = "invalid_worker_result"
        result = json.loads(raw)
        if not isinstance(result, dict) or set(result) != {"protocol", "python", "run", "failures", "errors", "skipped", "failed_cases"}:
            return report
        if type(result["protocol"]) is not int or result["protocol"] != 1:
            return report
        version = result["python"]
        if not isinstance(version, list) or len(version) != 3 or any(type(n) is not int or not 0 <= n <= 999 for n in version):
            return report
        if ".".join(map(str, version)) != python_version:
            report["reason"] = "tool_version_mismatch"
            return report
        counts = {key: result[key] for key in ("run", "failures", "errors", "skipped")}
        if any(type(n) is not int or not 0 <= n <= 64 for n in counts.values()):
            return report
        if counts["run"] != len(spec["cases"]) or sum(counts[k] for k in ("failures", "errors", "skipped")) > counts["run"]:
            return report
        if counts["errors"] or counts["skipped"]:
            report["reason"] = "incomplete_tests"
            return report
        failed = result["failed_cases"]
        if not isinstance(failed, list) or len(failed) != counts["failures"] or any(type(n) is not int or not 1 <= n <= counts["run"] for n in failed):
            return report
        if len(set(failed)) != len(failed):
            return report
        counts["failed_cases"] = failed
        report.update(state="FAIL" if counts["failures"] else "PASS", executed=True,
                      reason="assertion_mismatch" if counts["failures"] else "assertions_matched",
                      observed=counts, python_version=python_version)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        # Never export exception text, paths or child output.
        pass
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
    return report


def main(argv=None):
    parser = ArgumentParser(description="Run bundled synthetic vectors with an explicitly trusted Python.")
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--authorize-trusted-local-tests", action="store_true")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    # Refuse existing outputs before executing anything.
    try:
        args.output.mkdir(exist_ok=False)
        report = execute(args.spec, args.python, args.python_sha256, args.python_version,
                         authorized=args.authorize_trusted_local_tests, timeout=args.timeout)
        write_new(args.output / "report.json", report)
        text = ("# Trusted local test run\n\nState: " + report["state"] +
                "\n\nReason: " + report["reason"] + "\n\n" +
                "\n".join("- " + item for item in report["limitations"]) +
                "\n\nSee report.json for exact target/tool hashes and observed counts.\n")
        (args.output / "reviewer.md").write_text(text, encoding="utf-8")
        write_new(args.output / "checksums.json", {name: hashlib.sha256((args.output / name).read_bytes()).hexdigest()
                                                  for name in ("report.json", "reviewer.md")})
        print(json.dumps({"state": report["state"], "reason": report["reason"]}))
        return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[report["state"]]
    except (OSError, ValueError):
        print("Local test export blocked. Use a new writable output directory; no completion is claimed.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
