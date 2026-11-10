"""Offline artifact identity and source-test retest records; no artifact execution."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID

from .security_testing import digest, read_document, write_new, STATES
from .state_store import state_lock

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
HASH = re.compile(r"[a-f0-9]{64}\Z")


def artifact_identity(path: Path, kind: str) -> dict:
    if kind not in {"apk", "aab", "ipa", "source-archive"}:
        raise ValueError("unsupported_artifact")
    result = {"schema": "vulcanary.test-target.v1", "kind": kind,
              "state": "BLOCKED", "content_sha256": None, "size_bytes": None,
              "identity_verification": "unavailable", "executed": False,
              "scope": "offline-inventory-only"}
    try:
        if path.is_symlink() or not path.is_file():
            return result
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT_BYTES:
                return result
            checksum, total = hashlib.sha256(), 0
            while True:
                chunk = stream.read(min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - total))
                if not chunk:
                    break
                checksum.update(chunk)
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    return result
            after = os.fstat(stream.fileno())
            current = path.stat()
            signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            # Keep ctime for same-handle changes, not Windows handle/path skew.
            path_signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
            if signature(before) != signature(after) or path_signature(after) != path_signature(current) or total != before.st_size:
                return result
        result.update(state="NOT_RUN", content_sha256=checksum.hexdigest(), size_bytes=total,
                      identity_verification="local-bytes-hashed")
    except OSError:
        pass
    # Kind is operator-declared. No archive parsing, signing validation or device test.
    return result


def backend_identity(reference: str) -> dict:
    if not isinstance(reference, str) or not reference or len(reference.encode("utf-8")) > 4096:
        raise ValueError("invalid_reference")
    return {"schema": "vulcanary.test-target.v1", "kind": "backend-reference",
            "state": "NOT_RUN", "reference_sha256": hashlib.sha256(reference.encode()).hexdigest(),
            "identity_verification": "operator-reference-unverified", "executed": False,
            "scope": "offline-inventory-only"}


def _hash(value, nullable=False):
    if nullable and value is None:
        return value
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError("invalid_identity")
    return value


def summarize(report: dict) -> dict:
    if report.get("schema") != "vulcanary.security-test-run.v1" or report.get("policy_effect") != "none" or report.get("independent_certification") is not False:
        raise ValueError("invalid_report")
    if report.get("adapter") != "builtin-source-check.v1":
        raise ValueError("unsupported_adapter")
    run_id = str(UUID(report["run_id"]))
    checks, seen = [], set()
    for check in report["checks"]:
        identifier, state = check["id"], check["state"]
        if not isinstance(identifier, str) or not re.fullmatch(r"(?:registration|check-[0-9]{3})", identifier) or identifier in seen or state not in STATES:
            raise ValueError("invalid_check")
        if type(check["executed"]) is not bool or type(check["attempted"]) is not bool:
            raise ValueError("invalid_execution")
        completed = state in {"PASS", "FAIL"}
        if check["executed"] != completed or (completed and not check["attempted"]):
            raise ValueError("false_completion")
        seen.add(identifier)
        checks.append({"id": identifier, "state": state})
    if not 1 <= len(checks) <= 64:
        raise ValueError("invalid_checks")
    return {"run_id": run_id, "target_sha256": _hash(report["target_sha256"], True),
            "plan_sha256": _hash(report["plan_sha256"], True),
            "implementation_sha256": _hash(report["implementation_sha256"]),
            "ruleset_digest": _hash(report["ruleset_digest"], True),
            "adapter": report["adapter"], "checks": checks}


def _validate_summary(summary):
    # Reuse validation without importing arbitrary report text into history.
    fields = {"run_id", "target_sha256", "plan_sha256", "implementation_sha256", "ruleset_digest", "adapter", "checks"}
    if not isinstance(summary, dict) or set(summary) != fields:
        raise ValueError("invalid_history")
    report = {**summary, "schema": "vulcanary.security-test-run.v1", "policy_effect": "none", "independent_certification": False}
    report["checks"] = [{**item, "attempted": item["state"] in {"PASS", "FAIL"}, "executed": item["state"] in {"PASS", "FAIL"}} for item in summary["checks"]]
    if summarize(report) != summary:
        raise ValueError("invalid_history")


def load_record(history: Path, record_id: str) -> dict:
    _hash(record_id)
    path = history / (record_id + ".json")
    if path.is_symlink():
        raise ValueError("invalid_history")
    record = read_document(path)
    if set(record) != {"schema", "summary", "report_sha256", "previous"} or record["schema"] != "vulcanary.test-history.v1" or digest(record) != record_id:
        raise ValueError("changed_history")
    _hash(record["report_sha256"])
    _hash(record["previous"], True)
    _validate_summary(record["summary"])
    return record


def compare(before: dict, after: dict) -> dict:
    _validate_summary(before)
    _validate_summary(after)
    keys = ("plan_sha256", "adapter", "implementation_sha256", "ruleset_digest")
    incompatible = [key for key in keys if before[key] is None or after[key] is None or before[key] != after[key]]
    old = {item["id"]: item["state"] for item in before["checks"]}
    new = {item["id"]: item["state"] for item in after["checks"]}
    if old.keys() != new.keys():
        incompatible.append("check_ids")
    if before["target_sha256"] is None or after["target_sha256"] is None:
        incompatible.append("target_unavailable")
    elif before["target_sha256"] != after["target_sha256"]:
        incompatible.append("target_sha256")
    result = {"compatible": not incompatible, "incompatible_fields": incompatible,
              "target_changed": before["target_sha256"] != after["target_sha256"], "transitions": []}
    if incompatible:
        return result
    for identifier, state in new.items():
        previous = old[identifier]
        label = "not_comparable"
        if state == "BLOCKED":
            label = "blocked"
        elif previous == "FAIL" and state == "PASS":
            label = "passed_on_retest"
        elif previous == state == "FAIL":
            label = "persistent_failure"
        elif previous == "PASS" and state == "FAIL":
            label = "regression"
        elif previous == state == "PASS":
            label = "still_passing"
        result["transitions"].append({"id": identifier, "before": previous, "after": state, "result": label})
    return result


def append_run(history: Path, report: dict, previous: str | None = None) -> dict:
    summary = summarize(report)
    history.mkdir(parents=True, exist_ok=True)
    with state_lock(history / ".writer.lock"):
        prior = load_record(history, previous) if previous else None
        record = {"schema": "vulcanary.test-history.v1", "summary": summary,
                  "report_sha256": digest(report), "previous": previous}
        identifier = digest(record)
        path = history / (identifier + ".json")
        if path.exists():
            if load_record(history, identifier) != record:
                raise ValueError("history_conflict")
        else:
            write_new(path, record)
        return {"record_id": identifier, "comparison": compare(prior["summary"], summary) if prior else None}


def main(argv=None):
    from .cli_errors import ArgumentParser
    parser = ArgumentParser(description="Offline target inventory and verified local retest summaries.")
    commands = parser.add_subparsers(dest="command", required=True)
    artifact = commands.add_parser("artifact")
    artifact.add_argument("--path", type=Path, required=True)
    artifact.add_argument("--kind", choices=["apk", "aab", "ipa", "source-archive"], required=True)
    artifact.add_argument("--output", type=Path, required=True)
    backend = commands.add_parser("backend")
    backend.add_argument("--reference-file", type=Path, required=True)
    backend.add_argument("--output", type=Path, required=True)
    comparison = commands.add_parser("compare")
    comparison.add_argument("--history", type=Path, required=True)
    comparison.add_argument("--before", required=True)
    comparison.add_argument("--after", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            result = compare(load_record(args.history, args.before)["summary"], load_record(args.history, args.after)["summary"])
            print(json.dumps(result))
            return 0 if result["compatible"] else 2
        if args.command == "artifact":
            result = artifact_identity(args.path, args.kind)
        else:
            with args.reference_file.open("rb") as stream:
                reference = stream.read(4097)
            if len(reference) > 4096:
                raise ValueError("reference_limit")
            result = backend_identity(reference.decode("utf-8"))
        write_new(args.output, result)
        print(json.dumps(result))
        return 2 if result["state"] == "BLOCKED" else 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("Inventory operation blocked; check input, record integrity and unused output paths.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
