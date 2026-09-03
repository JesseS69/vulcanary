from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from .models import Finding
from .version import __version__


def render_markdown_summary(findings: list[Finding], repository: str) -> str:
    counts = {level: sum(finding.severity.name.lower() == level for finding in findings) for level in ("critical", "high", "medium", "low", "info", "unknown")}
    rows = "\n".join(f"| {level.title()} | {counts[level]} |" for level in counts)
    priority = sorted(findings, key=lambda item: (-int(item.severity), item.path, item.line))[:20]
    details = "\n".join(
        f"- **{finding.severity.name}** `{finding.rule_id}` — `{finding.path}:{finding.line}` — {finding.title}"
        for finding in priority
    ) or "- No findings."
    return (
        f"## Vulcanary security summary — {repository}\n\n"
        "| Severity | Findings |\n|---|---:|\n" + rows + "\n\n"
        f"### Highest-priority findings\n\n{details}\n\n"
        "_Source snippets, evidence, credentials, and absolute paths are excluded._\n"
    )


def _policy_identity(rule_id: str, path: str, evidence: str) -> str:
    return sha256(f"{rule_id}\0{path}\0{evidence}".encode()).hexdigest()


def baseline_identities(path: Path) -> set[str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        findings = document["findings"]
        required = ("rule_id", "path", "evidence", "fingerprint")
        if not isinstance(findings, list) or any(not isinstance(item, dict) or any(not isinstance(item.get(field), str) for field in required) for item in findings):
            raise TypeError
        return {_policy_identity(item["rule_id"], item["path"], item["evidence"]) for item in findings}
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise ValueError("Baseline must be a readable Vulcanary normalized JSON report") from error


def findings_new_since(findings: list[Finding], identities: set[str]) -> list[Finding]:
    return [finding for finding in findings if _policy_identity(finding.rule_id, finding.path, finding.evidence) not in identities]


def _github_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _github_property(value: str) -> str:
    return _github_data(value).replace(":", "%3A").replace(",", "%2C")


def render_github_annotations(findings: list[Finding]) -> str:
    levels = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "notice", "INFO": "notice", "UNKNOWN": "notice"}
    lines = []
    for finding in findings:
        level = levels[finding.severity.name]
        title = _github_property(f"Vulcanary {finding.severity.name.lower()}: {finding.rule_id}")
        path = _github_property(finding.path)
        message = _github_data(f"{finding.title}. {finding.remediation}".strip())
        lines.append(f"::{level} file={path},line={max(1, finding.line)},title={title}::{message}")
    return "\n".join(lines)


def write_json(findings: list[Finding], destination: Path, exceptions: list[dict] | None = None, policy: dict | None = None) -> None:
    document = {"version": 1, "findings": [f.to_dict() for f in findings]}
    if exceptions is not None:
        document["exceptions"] = exceptions
    if policy is not None:
        document["policy"] = policy
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def write_sarif(findings: list[Finding], destination: Path, policy: dict | None = None) -> None:
    rules = {}
    results = []
    levels = {"unknown": "note", "info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in findings:
        severity = finding.severity.name.lower()
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation},
            "properties": {"security-severity": str(max(0, int(finding.severity)) * 2.5)},
        }
        results.append({
            "ruleId": finding.rule_id,
            "level": levels[severity],
            "message": {"text": finding.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": {"startLine": finding.line}}}],
            "partialFingerprints": {"vulcanaryFingerprint/v1": finding.fingerprint},
        })
    run = {"tool": {"driver": {"name": "Vulcanary", "version": __version__, "rules": list(rules.values())}}, "results": results}
    if policy is not None:
        run["properties"] = {"vulcanaryPolicy": policy}
    document = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [run]}
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def render_console(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in findings:
        lines.append(f"{f.severity.name:<8} {f.rule_id:<24} {f.path}:{f.line}  {f.title}")
    counts = {name: sum(f.severity.name == name for f in findings) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")}
    summary = ", ".join(f"{value} {name.lower()}" for name, value in counts.items() if value)
    return "\n".join(lines) + f"\n\n{len(findings)} finding(s): {summary}"
