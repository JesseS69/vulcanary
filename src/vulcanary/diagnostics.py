"""Actionable dependency diagnostics, additive to legacy warning strings."""
import re


def history_failure(path: str) -> dict:
    return {"code": "history_scan_failed", "capability": "history", "path": path,
            "message": "History scanning did not complete; retained exposures are not a fresh result.",
            "action": "Check repository access and the configured absolute Gitleaks executable, then retry history scanning. Do not infer safety from this failure."}


def skipped_vex(path: str) -> dict:
    return {"code": "openvex_no_statements", "capability": "openvex", "path": path,
            "message": "OpenVEX export skipped: no dependency vulnerability statements were available.",
            "action": "Use normalized JSON for this scan. No VEX document was produced; choose a fresh output path if an older file exists."}


def dataflow_diagnostics(report: dict, parse_paths: list[str]) -> list[dict]:
    """Derived guidance only: never changes exposure or gap identities or policy."""
    actions = {
        "module_limit": "Raise --max-modules or scan a smaller source tree, then rerun.",
        "call_limit": "Raise --max-calls or scan a smaller source tree, then rerun.",
        "time_limit": "Raise --timeout-seconds or scan a smaller source tree, then rerun.",
        "source_size_limit": "Split the source input or review it manually; the configured source-size limit prevented analysis.",
        "depth_limit": "Raise --max-depth within a suitable resource budget, then rerun.",
        "missing_module": "Include the referenced source module in the scan or review the unresolved call manually; do not execute imports to resolve it.",
        "missing_base": "Include the base class source or review the inherited behavior manually.",
        "recursion_cycle": "Review the recursive path manually; raising depth alone does not resolve a cycle.",
    }
    records = []
    for kind, entries in (("gap", report["unmodeled_constructs"]), ("limit", report["analysis_limits"]), ("truncation", report["analysis_truncations"])):
        for entry in entries:
            category = entry.get("category", "depth_limit")
            records.append({"code": f"dataflow_{category}", "capability": "experimental_dataflow",
                            "path": entry.get("path"), "line": entry.get("sink_line", entry.get("line")),
                            "message": f"Experimental analysis reported a {kind}; this is not evidence of safety.",
                            "action": actions.get(category, "Review the unresolved source-to-sink path manually or with an independent analyzer; this construct is not fully modeled.")})
    for path in parse_paths:
        records.append({"code": "dataflow_parse_failed", "capability": "experimental_dataflow", "path": path,
                        "message": "Python source could not be read or parsed; its analysis is incomplete.",
                        "action": "Check access, encoding and Python syntax, then rerun. Source text and parser exception details are intentionally omitted."})
    return records


def dependency_diagnostics(unresolved: list[str], service_warning: str | None = None) -> list[dict]:
    records = []
    for warning in unresolved:
        path, _, detail = warning.partition(":")
        record = {"code": "dependency_input_unresolved", "path": path, "capability": "dependency",
                  "message": warning,
                  "action": "Generate a supported resolved lockfile or CycloneDX inventory using your trusted build environment, then rescan."}
        size = re.search(r"input is (\d+) bytes and exceeds the (\d+)-byte limit", detail)
        if size:
            actual, limit = map(int, size.groups())
            record.update(code="dependency_input_too_large", actual_bytes=actual, limit_bytes=limit,
                          message=f"{path}: dependency input is {actual / 1048576:.1f} MiB; the limit is {limit / 1048576:g} MiB.",
                          action="Split the scanned project or supply a smaller resolved inventory in a separate scan directory; the oversized input was not evaluated.")
        elif "invalid" in detail.lower() or "unreadable" in detail.lower():
            record.update(code="dependency_input_invalid",
                          action="Check file encoding and structure or regenerate this input with your trusted package manager; then rescan.")
        elif path.lower().endswith(".txt") or path.lower().endswith("pipfile.lock"):
            record.update(code="dependency_version_unresolved",
                          action="Provide exact resolved versions in a supported lockfile; a requirement range is not an installed version.")
        records.append(record)
    if service_warning and "OSV" in service_warning:
        records.append({"code": "advisory_lookup_unavailable", "path": None, "capability": "dependency",
                        "message": "Advisory lookup did not complete.",
                        "action": "Check network access to OSV and retry; missing advisory results do not mean the dependencies are safe."})
    elif service_warning and not records:
        records.append({"code": "dependency_coverage_incomplete", "path": None, "capability": "dependency",
                        "message": "Some dependency inputs were not evaluated.",
                        "action": "Check dependency coverage details and supply supported resolved inputs, then rescan; incomplete results do not establish safety."})
    return records
