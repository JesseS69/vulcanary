from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .models import Finding, Severity


class AdapterError(ValueError):
    """Raised when an external scanner report cannot be safely normalized."""


def _severity(value: object, default: Severity = Severity.MEDIUM) -> Severity:
    aliases = {"UNKNOWN": default, "NEGLIGIBLE": Severity.INFO, "WARNING": Severity.MEDIUM, "ERROR": Severity.HIGH}
    name = str(value or "").upper()
    return aliases.get(name, Severity.__members__.get(name, default))


def _path(value: object, root: Path) -> str:
    raw = str(value or "unknown").replace("\\", "/")
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            raw = candidate.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return "external-report"
    normalized = PurePosixPath(raw)
    if ".." in normalized.parts:
        return "external-report"
    return normalized.as_posix().lstrip("./") or "external-report"


def _line(value: object) -> int:
    try:
        return max(1, int(value or 1))
    except (TypeError, ValueError):
        return 1


def _text(value: object, fallback: str = "External scanner finding") -> str:
    return str(value).strip() if value is not None and str(value).strip() else fallback


def _finding(*, scanner: str, rule: object, title: object, description: object, severity: object,
             category: str, path: object, line: object, root: Path, remediation: object = "",
             metadata: dict[str, Any] | None = None, secret: bool = False) -> Finding:
    rule_id = _text(rule, "unknown")
    return Finding(
        rule_id=f"{scanner.upper()}-{rule_id}", title=_text(title, rule_id),
        description=_text(description), severity=_severity(severity), category=category,
        path=_path(path, root), line=_line(line), evidence="[redacted]" if secret else "",
        remediation=_text(remediation, "Review and remediate the external scanner finding."),
        scanner=scanner, metadata={key: value for key, value in (metadata or {}).items() if value not in (None, "", [])},
    )


def _semgrep(document: Any, root: Path) -> list[Finding]:
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise AdapterError("Semgrep report must contain a results array")
    findings = []
    for item in document["results"]:
        if not isinstance(item, dict) or not isinstance(item.get("extra"), dict):
            raise AdapterError("Semgrep result is malformed")
        extra = item["extra"]
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        findings.append(_finding(scanner="semgrep", rule=item.get("check_id"), title=extra.get("message"),
            description=extra.get("message"), severity=extra.get("severity"), category="sast",
            path=item.get("path"), line=(item.get("start") or {}).get("line") if isinstance(item.get("start"), dict) else 1,
            root=root, remediation=metadata.get("fix") or metadata.get("shortlink"),
            metadata={"confidence": metadata.get("confidence"), "external_rule_id": item.get("check_id")}))
    return findings


def _gitleaks(document: Any, root: Path) -> list[Finding]:
    if not isinstance(document, list):
        raise AdapterError("Gitleaks report must be an array")
    findings = []
    for item in document:
        if not isinstance(item, dict):
            raise AdapterError("Gitleaks result is malformed")
        findings.append(_finding(scanner="gitleaks", rule=item.get("RuleID"), title=item.get("Description"),
            description=item.get("Description"), severity="critical", category="secret", path=item.get("File"),
            line=item.get("StartLine"), root=root, remediation="Revoke the credential, remove it from history, and use a secret store.",
            metadata={"commit": item.get("Commit"), "external_rule_id": item.get("RuleID")}, secret=True))
    return findings


def _trivy(document: Any, root: Path) -> list[Finding]:
    if not isinstance(document, dict) or not isinstance(document.get("SchemaVersion"), int):
        raise AdapterError("Trivy report must contain an integer SchemaVersion")
    results = document.get("Results", [])
    if not isinstance(results, list):
        raise AdapterError("Trivy Results must be an array when present")
    findings = []
    for result in results:
        if not isinstance(result, dict):
            raise AdapterError("Trivy result is malformed")
        target = result.get("Target")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                raise AdapterError("Trivy vulnerability is malformed")
            findings.append(_finding(scanner="trivy", rule=item.get("VulnerabilityID"), title=item.get("Title"),
                description=item.get("Description"), severity=item.get("Severity"), category="dependency",
                path=target, line=1, root=root, remediation=f"Upgrade {item.get('PkgName', 'the package')} to {item.get('FixedVersion') or 'a patched version'}.",
                metadata={"package": item.get("PkgName"), "installed_version": item.get("InstalledVersion"), "fixed_version": item.get("FixedVersion"), "advisory": item.get("PrimaryURL")}))
        for item in result.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                raise AdapterError("Trivy misconfiguration is malformed")
            cause = item.get("CauseMetadata") if isinstance(item.get("CauseMetadata"), dict) else {}
            findings.append(_finding(scanner="trivy", rule=item.get("ID") or item.get("AVDID"), title=item.get("Title"),
                description=item.get("Description") or item.get("Message"), severity=item.get("Severity"), category="iac",
                path=target, line=cause.get("StartLine"), root=root, remediation=item.get("Resolution"), metadata={"namespace": item.get("Namespace")}))
    return findings


def _checkov(document: Any, root: Path) -> list[Finding]:
    reports = document if isinstance(document, list) else [document]
    if not reports or any(not isinstance(report, dict) or not isinstance(report.get("results"), dict) for report in reports):
        raise AdapterError("Checkov report must contain a results object")
    findings = []
    for report in reports:
        failed = report["results"].get("failed_checks")
        if not isinstance(failed, list):
            raise AdapterError("Checkov results must contain a failed_checks array")
        for item in failed:
            if not isinstance(item, dict):
                raise AdapterError("Checkov result is malformed")
            lines = item.get("file_line_range") or [1]
            findings.append(_finding(scanner="checkov", rule=item.get("check_id"), title=item.get("check_name"),
                description=item.get("check_name"), severity=(item.get("severity") or "medium"), category="iac",
                path=item.get("file_path"), line=lines[0] if isinstance(lines, list) and lines else 1, root=root,
                remediation=item.get("guideline"), metadata={"resource": item.get("resource"), "external_rule_id": item.get("check_id")}))
    return findings


PARSERS: dict[str, Callable[[Any, Path], list[Finding]]] = {
    "semgrep": _semgrep, "gitleaks": _gitleaks, "trivy": _trivy, "checkov": _checkov,
}


def import_report(scanner: str, report: Path, root: Path) -> list[Finding]:
    try:
        parser = PARSERS[scanner]
    except KeyError as error:
        raise AdapterError(f"Unsupported external scanner: {scanner}") from error
    try:
        document = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AdapterError(f"{scanner} report is not readable JSON: {report}") from error
    return parser(document, root)
