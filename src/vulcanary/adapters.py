from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .models import Finding, Severity


class AdapterError(ValueError):
    """Raised when an external scanner report cannot be safely normalized."""


def _severity(value: object, default: Severity = Severity.MEDIUM) -> Severity:
    aliases = {"UNKNOWN": default, "NEGLIGIBLE": Severity.INFO, "NONE": Severity.INFO, "NOTE": Severity.INFO, "WARNING": Severity.MEDIUM, "ERROR": Severity.HIGH}
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
             metadata: dict[str, Any] | None = None, secret: bool = False, evidence: object = "") -> Finding:
    rule_id = _text(rule, "unknown")
    return Finding(
        rule_id=f"{scanner.upper()}-{rule_id}", title=_text(title, rule_id),
        description=_text(description), severity=_severity(severity), category=category,
        path=_path(path, root), line=_line(line), evidence="[redacted]" if secret else _text(evidence, ""),
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
    artifact_type = str(document.get("ArtifactType") or "filesystem")
    is_image = artifact_type in {"container_image", "container-image", "image"}
    image_name = _text(document.get("ArtifactName"), "local-image") if is_image else None
    for result in results:
        if not isinstance(result, dict):
            raise AdapterError("Trivy result is malformed")
        target = result.get("Target")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                raise AdapterError("Trivy vulnerability is malformed")
            findings.append(_finding(scanner="trivy", rule=item.get("VulnerabilityID"), title=item.get("Title"),
                description=item.get("Description"), severity=item.get("Severity"), category="container" if is_image else "dependency",
                path=f"container-image/{target or 'packages'}" if is_image else target, line=1, root=root,
                remediation=f"Upgrade {item.get('PkgName', 'the package')} to {item.get('FixedVersion') or 'a patched version'} and rebuild the image from a reviewed base.",
                evidence=f"{item.get('PkgName', 'package')}@{item.get('InstalledVersion', 'unknown')}",
                metadata={"package": item.get("PkgName"), "installed_version": item.get("InstalledVersion"), "current_version": item.get("InstalledVersion"), "fixed_version": item.get("FixedVersion"), "advisory": item.get("VulnerabilityID"), "artifact_type": artifact_type, "image": image_name, "package_type": result.get("Type")}))
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


def _zap(document: Any, root: Path) -> list[Finding]:
    if not isinstance(document, dict) or not isinstance(document.get("site"), list):
        raise AdapterError("ZAP report must contain a site array")
    findings = []
    levels = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
    for site in document["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts", []), list):
            raise AdapterError("ZAP site is malformed")
        host = _text(site.get("@host") or site.get("@name"), "authorized-target")
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                raise AdapterError("ZAP alert is malformed")
            instances = alert.get("instances") if isinstance(alert.get("instances"), list) else []
            location = instances[0].get("uri") if instances and isinstance(instances[0], dict) else host
            findings.append(_finding(
                scanner="zap", rule=alert.get("pluginid") or alert.get("alertRef"),
                title=alert.get("alert"), description=alert.get("desc"),
                severity=levels.get(str(alert.get("riskcode")), alert.get("riskdesc")),
                category="dast", path=f"web-target/{host}", line=1, root=root,
                remediation=alert.get("solution"), evidence="[response evidence excluded]",
                metadata={"target": location, "confidence": alert.get("confidence"), "cwe": alert.get("cweid")},
            ))
    return findings


def _sarif(document: Any, root: Path) -> list[Finding]:
    if not isinstance(document, dict) or document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise AdapterError("SARIF report must be a SARIF 2.1.0 document with runs")
    findings = []
    for run in document["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise AdapterError("SARIF run is malformed")
        driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), dict) else {}
        if not isinstance(driver, dict):
            raise AdapterError("SARIF tool driver is malformed")
        scanner = re_safe_name(driver.get("name") or "sarif")
        rule_list = driver.get("rules", [])
        if not isinstance(rule_list, list):
            raise AdapterError("SARIF driver rules must be an array")
        rules = {str(rule.get("id")): rule for rule in rule_list if isinstance(rule, dict)}
        for item in run.get("results", []):
            if not isinstance(item, dict):
                raise AdapterError("SARIF result is malformed")
            rule_id = str(item.get("ruleId") or "unknown")
            rule = rules.get(rule_id, {})
            message = item.get("message", {})
            title = message.get("text") if isinstance(message, dict) else message
            locations = item.get("locations") if isinstance(item.get("locations"), list) else []
            physical = (((locations[0].get("physicalLocation") or {}) if locations and isinstance(locations[0], dict) else {}))
            artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
            region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
            help_text = rule.get("help", {}) if isinstance(rule.get("help"), dict) else {}
            findings.append(_finding(
                scanner=scanner, rule=rule_id, title=title, description=title,
                severity=item.get("level"), category="external",
                path=artifact.get("uri"), line=region.get("startLine"), root=root,
                remediation=help_text.get("text") or rule.get("helpUri"),
                metadata={"external_rule_id": rule_id},
            ))
    return findings


def re_safe_name(value: object) -> str:
    normalized = "".join(character.lower() if character.isalnum() else "-" for character in str(value))
    return normalized.strip("-")[:40] or "sarif"


def _prowler(document: Any, root: Path) -> list[Finding]:
    records = document if isinstance(document, list) else document.get("findings") if isinstance(document, dict) else None
    if not isinstance(records, list):
        raise AdapterError("Prowler report must be an OCSF findings array")
    findings = []
    for item in records:
        if not isinstance(item, dict):
            raise AdapterError("Prowler finding is malformed")
        status = str(item.get("status_code") or item.get("status") or "FAIL").upper()
        if status in {"PASS", "2", "RESOLVED", "SUPPRESSED"}:
            continue
        finding_info = item.get("finding_info") if isinstance(item.get("finding_info"), dict) else {}
        resources = item.get("resources") if isinstance(item.get("resources"), list) else []
        resource = resources[0] if resources and isinstance(resources[0], dict) else {}
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        remediation = item.get("remediation") if isinstance(item.get("remediation"), dict) else {}
        title = finding_info.get("title") or item.get("message") or item.get("check_title")
        raw_severity = item.get("severity")
        if not raw_severity:
            raw_severity = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}.get(item.get("severity_id"), "medium")
        findings.append(_finding(
            scanner="prowler", rule=finding_info.get("uid") or item.get("check_id") or item.get("event_code"),
            title=title, description=item.get("message") or item.get("status_detail") or title,
            severity=raw_severity, category="cloud",
            path=f"cloud-resource/{_text(resource.get('name') or resource.get('uid'), 'unknown')}", line=1, root=root,
            remediation=remediation.get("desc") or remediation.get("description"),
            metadata={"provider": metadata.get("product", {}).get("vendor_name") if isinstance(metadata.get("product"), dict) else item.get("cloud_provider"), "region": resource.get("region"), "resource_uid": resource.get("uid")},
        ))
    return findings


PARSERS: dict[str, Callable[[Any, Path], list[Finding]]] = {
    "semgrep": _semgrep, "gitleaks": _gitleaks, "trivy": _trivy, "trivy-image": _trivy, "checkov": _checkov,
    "zap": _zap, "sarif": _sarif, "prowler": _prowler,
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


def import_document(scanner: str, document: Any, root: Path) -> list[Finding]:
    """Normalize an in-memory scanner report without writing sensitive content to disk."""
    parser = PARSERS.get(scanner)
    if parser is None:
        raise AdapterError(f"Unsupported scanner: {scanner}")
    return parser(document, root)
