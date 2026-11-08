"""Opt-in, offline test orchestration. v1 executes analysis, never target code."""
from __future__ import annotations

import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import uuid

from .cli_errors import ArgumentParser
from .config import Config
from .scanners import scan, rules_for, ruleset_manifest
from .version import __version__

MAX_BYTES = 256 * 1024
STATES = ("PASS", "FAIL", "BLOCKED", "NOT_RUN", "DEFERRED")
SCOPE = {"environment": "isolated-source-fixture", "synthetic_data": True,
         "permitted_actions": ["builtin-source-check"], "accounts": [], "endpoints": [],
         "production_authorized": False}
LIMITS = ["Python source-pattern assertions only; not application runtime behavior.",
          "No dependency, backend, device, cryptographic or network tests executed.",
          "Temporary file isolation is not an OS sandbox; no target code is executed.",
          "Operator declarations and hashes are not independent authorization or certification."]


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode()).hexdigest()


def read_document(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input_limit")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_document") from None
    if not isinstance(document, dict):
        raise ValueError("invalid_document")
    return document


def validate_spec(spec: dict) -> None:
    if set(spec) != {"files", "checks"}:
        raise ValueError("invalid_spec")
    files, checks = spec["files"], spec["checks"]
    if not isinstance(files, list) or not 1 <= len(files) <= 16:
        raise ValueError("invalid_files")
    for source in files:
        if not isinstance(source, str) or len(source.encode("utf-8")) > 65536:
            raise ValueError("invalid_source")
        if "vulcanary:ignore" in source:
            raise ValueError("suppression_not_supported")
        # Syntax validation, not execution. This slice refuses fallback analysis.
        ast.parse(source)
    if not isinstance(checks, list) or not 1 <= len(checks) <= 64:
        raise ValueError("invalid_checks")
    rules = {rule.id for rule in rules_for(Config()) if rule.category == "secret" or ".py" in rule.extensions}
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("invalid_check")
        if check.get("method") == "automated":
            if set(check) != {"method", "rule", "expected_count"} or check["rule"] not in rules:
                raise ValueError("invalid_check")
            if type(check["expected_count"]) is not int or not 0 <= check["expected_count"] <= 10000:
                raise ValueError("invalid_expectation")
        elif check.get("method") in {"manual", "deferred"}:
            if set(check) != {"method", "kind"} or check["kind"] not in {"device-privacy", "accessibility", "backend-authorization", "crypto-integration"}:
                raise ValueError("invalid_check")
        else:
            raise ValueError("invalid_method")


def write_new(path: Path, document: dict) -> None:
    # Refuse overwrite (including symlinks); never update live application state.
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, ensure_ascii=True) + "\n")


def register(spec_path: Path, destination: Path, *, authorized: bool = False) -> dict:
    if not authorized:
        raise ValueError("authorization_required")
    spec = read_document(spec_path)
    validate_spec(spec)
    target = {"schema": "vulcanary.security-target.v1", "scope": SCOPE,
              "target_sha256": digest(spec["files"]), "plan_sha256": digest(spec["checks"]),
              "spec": spec}
    if len(json.dumps(target, ensure_ascii=True).encode()) > MAX_BYTES - 4096:
        raise ValueError("input_limit")
    write_new(destination, target)
    return target


def _registered(path: Path) -> dict:
    target = read_document(path)
    if set(target) != {"schema", "scope", "target_sha256", "plan_sha256", "spec"} or target["schema"] != "vulcanary.security-target.v1" or target["scope"] != SCOPE:
        raise ValueError("invalid_target")
    validate_spec(target["spec"])
    if target["target_sha256"] != digest(target["spec"]["files"]) or target["plan_sha256"] != digest(target["spec"]["checks"]):
        raise ValueError("target_changed")
    return target


def execute(target_path: Path) -> dict:
    implementation = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                      for name in ("security_testing.py", "scanners.py", "config.py", "models.py")}
    report = {"schema": "vulcanary.security-test-run.v1", "run_id": str(uuid.uuid4()),
              "started_at": datetime.now(timezone.utc).isoformat(),
              "producer_version": __version__, "implementation_sha256": digest(implementation),
              "adapter": "builtin-source-check.v1", "evidence_method": "automated-static-analysis",
              "policy_effect": "none", "independent_certification": False,
              "target_sha256": None, "plan_sha256": None, "ruleset_digest": None,
              "coverage_limits": LIMITS, "checks": [], "evidence": [],
              "files_analyzed": 0, "cleanup": "not_created"}
    try:
        target = _registered(target_path)
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, RecursionError):
        report["checks"] = [{"id": "registration", "state": "BLOCKED", "executed": False,
                             "attempted": False, "expected": "valid registered isolated target", "observed": None,
                             "reason": "Target is invalid, unavailable or changed; re-register after review."}]
    else:
        report.update(target_sha256=target["target_sha256"], plan_sha256=target["plan_sha256"])
        spec = target["spec"]
        for index, check in enumerate(spec["checks"]):
            automatic = check["method"] == "automated"
            report["checks"].append({"id": f"check-{index + 1:03d}", "state": "DEFERRED" if check["method"] == "deferred" else "NOT_RUN",
                "executed": False, "attempted": False, "method": check["method"],
                "expected": {"rule": check["rule"], "count": check["expected_count"]} if automatic else check["kind"],
                "observed": None, "reason": "Awaiting adapter execution." if automatic else "Human/device evidence required; not executed by this adapter."})
        automatic = [check for check in report["checks"] if check["method"] == "automated"]
        if automatic:
            try:
                with tempfile.TemporaryDirectory(prefix=f"vulcanary-security-{report['run_id']}-") as directory:
                    report["cleanup"] = "pending"
                    root = Path(directory)
                    for index, source in enumerate(spec["files"]):
                        (root / f"source-{index + 1:03d}.py").write_text(source, encoding="utf-8", newline="")
                    config = Config()
                    report["ruleset_digest"] = ruleset_manifest(config)["digest"]
                    names = {f"source-{index + 1:03d}.py" for index in range(len(spec["files"]))}
                    for check in automatic:
                        check["attempted"] = True
                    findings = scan(root, config, expected_files=names)
                    # Re-read exact staged inputs before claiming completed analysis.
                    if [ (root / f"source-{index + 1:03d}.py").read_text(encoding="utf-8") for index in range(len(spec["files"])) ] != [source.replace("\r\n", "\n").replace("\r", "\n") for source in spec["files"]]:
                        raise ValueError("staged_target_changed")
                    # Allowlist evidence fields; never serialize Finding.to_dict().
                    known = {rule.id for rule in rules_for(config)}
                    if any(item.path not in names or item.rule_id not in known or type(item.line) is not int or item.line < 1 for item in findings):
                        raise ValueError("invalid_adapter_result")
                    evidence = sorted([{"rule": item.rule_id, "file": item.path, "line": item.line} for item in findings], key=lambda item: (item["file"], item["line"], item["rule"]))
                report["cleanup"] = "complete"
                report["evidence"] = evidence
                report["files_analyzed"] = len(spec["files"])
                counts = Counter(item["rule"] for item in evidence)
                for check in automatic:
                    check.update(executed=True, observed={"count": counts[check["expected"]["rule"]]},
                                 state="PASS" if counts[check["expected"]["rule"]] == check["expected"]["count"] else "FAIL",
                                 reason="Observed rule count compared with the registered expectation.")
            except (OSError, ValueError, TypeError, RuntimeError, RecursionError):
                report["cleanup"] = "not_confirmed"
                for check in automatic:
                    check.update(state="BLOCKED", reason="Adapter or cleanup could not complete; no passing assertion is issued.")
    counts = Counter(check["state"] for check in report["checks"])
    report["counts"] = {state: counts[state] for state in STATES}
    report["state"] = next(state for state in ("BLOCKED", "FAIL", "NOT_RUN", "DEFERRED", "PASS") if counts[state])
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    return report


def export_package(report: dict, destination: Path) -> None:
    destination.mkdir()  # No overwrite or merging into an existing evidence package.
    write_new(destination / "report.json", report)
    lines = ["# Internal security test evidence", "", "Not independent certification.", "",
             f"Run: {report['run_id']}", f"State: {report['state']}",
             f"Target SHA-256: {report['target_sha256']}", f"Plan SHA-256: {report['plan_sha256']}",
             f"Implementation SHA-256: {report['implementation_sha256']}",
             f"Vulcanary: {report['producer_version']}; ruleset: {report['ruleset_digest']}", "",
             "PASS means a declared assertion matched, not that an application is secure.", "",
             "## Checks", ""]
    lines += [f"- {item['id']}: {item['state']} — expected {json.dumps(item['expected'])}; observed {json.dumps(item['observed'])}. {item['reason']}" for item in report["checks"]]
    lines += ["", "## Coverage limits", "", *[f"- {item}" for item in report["coverage_limits"]], "",
              "## Reproduce", "", "Obtain the private registered target matching both hashes above.",
              "Run: python -m vulcanary.security_testing run --target TARGET.json --output NEW_DIRECTORY",
              "Use the recorded Vulcanary version, implementation and ruleset digests. Development builds may share a package version.",
              "Source files are ordinal IDs in the private snapshot. Check report.json for rule/file/line observations.",
              "Retests create a new run/package; compare check IDs only when the plan hash matches."]
    (destination / "reviewer.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    hashes = {name: hashlib.sha256((destination / name).read_bytes()).hexdigest() for name in ("report.json", "reviewer.md")}
    write_new(destination / "checksums.json", hashes)


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="Offline isolated source-test workflow; never executes application code.")
    commands = parser.add_subparsers(dest="command", required=True)
    registration = commands.add_parser("register")
    registration.add_argument("--spec", type=Path, required=True)
    registration.add_argument("--target", type=Path, required=True)
    registration.add_argument("--authorize-isolated-synthetic-source", action="store_true")
    run = commands.add_parser("run")
    run.add_argument("--target", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "register":
            target = register(args.spec, args.target, authorized=args.authorize_isolated_synthetic_source)
            print(json.dumps({"state": "NOT_RUN", "target_sha256": target["target_sha256"], "plan_sha256": target["plan_sha256"]}))
            return 0
        report = execute(args.target)
        export_package(report, args.output)
        print(json.dumps({"state": report["state"], "counts": report["counts"]}))
        return 2 if report["counts"]["BLOCKED"] else 1 if report["counts"]["FAIL"] else 0
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, RecursionError):
        print("Security-test operation blocked. Check bounded input, explicit authorization and unused output paths; no completion is claimed.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
