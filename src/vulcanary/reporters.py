from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def write_json(findings: list[Finding], destination: Path) -> None:
    destination.write_text(json.dumps({"version": 1, "findings": [f.to_dict() for f in findings]}, indent=2) + "\n", encoding="utf-8")


def write_sarif(findings: list[Finding], destination: Path) -> None:
    rules = {}
    results = []
    levels = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in findings:
        severity = finding.severity.name.lower()
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation},
            "properties": {"security-severity": str(int(finding.severity) * 2.5)},
        }
        results.append({
            "ruleId": finding.rule_id,
            "level": levels[severity],
            "message": {"text": finding.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": {"startLine": finding.line}}}],
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
        })
    document = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Vulcanary", "version": "0.1.0", "rules": list(rules.values())}}, "results": results}]}
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def render_console(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in findings:
        lines.append(f"{f.severity.name:<8} {f.rule_id:<24} {f.path}:{f.line}  {f.title}")
    counts = {name: sum(f.severity.name == name for f in findings) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    summary = ", ".join(f"{value} {name.lower()}" for name, value in counts.items() if value)
    return "\n".join(lines) + f"\n\n{len(findings)} finding(s): {summary}"
