"""Actionable dependency diagnostics, additive to legacy warning strings."""
import re


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
    return records
