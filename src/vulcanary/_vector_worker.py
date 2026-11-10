"""Trusted, standalone unittest worker. Never load test code from the target."""
import hashlib
import json
from pathlib import Path
import sys
import unittest


def main():
    # The controller installs process containment before releasing this gate.
    if sys.stdin.buffer.readline(4) != b"go\n":
        return 2
    document = json.loads(Path("vectors.json").read_text(encoding="utf-8"))
    suite = unittest.TestSuite()
    for index, item in enumerate(document["cases"], 1):
        def assertion(item=item):
            actual = hashlib.sha256(bytes.fromhex(item["input_hex"])).hexdigest()
            if actual != item["expected_sha256"]:
                raise AssertionError("vector mismatch")
        case = unittest.FunctionTestCase(assertion)
        case.vector_id = index
        suite.addTest(case)
    result = unittest.TestResult()
    suite.run(result)
    # Exceptions, tracebacks, vector data and test names never leave the worker.
    print(json.dumps({"protocol": 1, "python": list(sys.version_info[:3]),
                      "run": result.testsRun, "failures": len(result.failures),
                      "errors": len(result.errors), "skipped": len(result.skipped),
                      "failed_cases": [case.vector_id for case, _ in result.failures]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
