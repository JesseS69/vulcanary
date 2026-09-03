from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .adapters import AdapterError, import_document


class HistoryScanError(ValueError):
    """Raised when the explicitly configured history scanner cannot run safely."""


def validate_executable(value: str | Path) -> Path:
    executable = Path(value).expanduser()
    if not executable.is_absolute():
        raise HistoryScanError("Gitleaks executable must be an explicit absolute path")
    resolved = executable.resolve()
    if not resolved.is_file():
        raise HistoryScanError(f"Gitleaks executable does not exist: {resolved}")
    return resolved


def git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root), "rev-parse", "HEAD"],
        cwd=Path.home(), text=True, capture_output=True, timeout=15,
    )
    head = result.stdout.strip()
    if result.returncode or len(head) != 40 or any(character not in "0123456789abcdef" for character in head.lower()):
        raise HistoryScanError("Repository HEAD could not be resolved")
    return head


def _is_ancestor(root: Path, older: str, newer: str) -> bool:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root), "merge-base", "--is-ancestor", older, newer],
        cwd=Path.home(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
    )
    return result.returncode == 0


def _oldest_key(item: dict) -> tuple[str, str]:
    return str(item.get("Date") or "9999"), str(item.get("Commit") or "")


def scan_history(root: Path, executable: str | Path, previous_head: str | None = None, timeout: int = 600) -> dict:
    """Scan Git history in memory and return location-collapsed, redacted exposures."""
    repository = root.resolve()
    if not (repository / ".git").exists():
        raise HistoryScanError("Git-history scanning requires a Git repository")
    binary = validate_executable(executable)
    head = git_head(repository)
    if previous_head and (len(previous_head) != 40 or any(character not in "0123456789abcdef" for character in previous_head.lower())):
        previous_head = None
    incremental = bool(previous_head and previous_head != head and _is_ancestor(repository, previous_head, head))
    unchanged = previous_head == head
    if unchanged:
        return {"head": head, "mode": "unchanged", "findings": [], "scanned_at": datetime.now(timezone.utc).isoformat()}
    log_opts = f"--no-textconv {previous_head}..{head}" if incremental else "--no-textconv --full-history --all --diff-filter=tuxdb"
    command = [
        str(binary), "git", "--no-banner", "--no-color", "--redact=100",
        "--report-format=json", "--report-path=-", f"--log-opts={log_opts}", str(repository),
    ]
    try:
        completed = subprocess.run(command, cwd=Path.home(), text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HistoryScanError(f"Gitleaks history scan failed: {error}") from error
    if completed.returncode not in {0, 1}:
        raise HistoryScanError(f"Gitleaks history scan failed with exit code {completed.returncode}")
    try:
        document = json.loads(completed.stdout or "[]")
        findings = import_document("gitleaks", document, repository)
    except (ValueError, json.JSONDecodeError, AdapterError) as error:
        raise HistoryScanError("Gitleaks returned an invalid JSON report") from error
    grouped: dict[tuple[str, str, int], list[tuple[dict, object]]] = {}
    for raw, finding in zip(document, findings):
        grouped.setdefault((finding.rule_id, finding.path, finding.line), []).append((raw, finding))
    exposures = []
    for occurrences in grouped.values():
        ordered = sorted(occurrences, key=lambda pair: _oldest_key(pair[0]))
        oldest_raw, oldest = ordered[0]
        exposures.append(dict(
            oldest.to_dict(), severity="unknown", lifecycle="credential_rotation",
            metadata={
                "first_commit": oldest_raw.get("Commit"), "latest_commit": ordered[-1][0].get("Commit"),
                "first_observed_at": oldest_raw.get("Date"), "occurrence_count": len(ordered),
                "secret_retained": False, "history_exposure": True,
            },
        ))
    exposures.sort(key=lambda item: (item["path"], item["line"], item["rule_id"]))
    return {
        "head": head, "mode": "incremental" if incremental else "full", "findings": exposures,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
