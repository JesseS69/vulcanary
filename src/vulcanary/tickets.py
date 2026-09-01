from __future__ import annotations

import csv
import io
import json


def finding_ticket(finding: dict) -> dict:
    """Build a source-free, credential-free local handoff record."""
    metadata = finding.get("metadata", {})
    return {
        "version": 1,
        "title": f"[{finding['severity'].upper()}] {finding['title']}",
        "repository": finding["repository"],
        "rule_id": finding["rule_id"],
        "severity": finding["severity"],
        "category": finding["category"],
        "scanner": finding["scanner"],
        "location": {"path": finding["path"], "line": finding["line"]},
        "description": finding["description"],
        "remediation": finding.get("remediation", ""),
        "fingerprint": finding["fingerprint"],
        "advisory": metadata.get("advisory"),
        "fixed_version": metadata.get("fixed_version"),
        "owner": metadata.get("policy", {}).get("owner"),
        "deadline": metadata.get("policy", {}).get("deadline"),
        "priority": metadata.get("priority"),
        "source_excluded": True,
    }


def ticket_markdown(ticket: dict) -> str:
    fields = [
        ("Repository", ticket["repository"]), ("Rule", ticket["rule_id"]),
        ("Severity", ticket["severity"]), ("Scanner", ticket["scanner"]),
        ("Location", f"{ticket['location']['path']}:{ticket['location']['line']}"),
        ("Fingerprint", ticket["fingerprint"]), ("Owner", ticket.get("owner") or "Unassigned"),
        ("Deadline", ticket.get("deadline") or "Not established"),
    ]
    rows = "\n".join(f"- **{label}:** {value}" for label, value in fields)
    optional = ""
    if ticket.get("advisory"):
        optional += f"\n- **Advisory:** {ticket['advisory']}"
    if ticket.get("fixed_version"):
        optional += f"\n- **Patched version:** {ticket['fixed_version']}"
    return (
        f"# {ticket['title']}\n\n{rows}{optional}\n\n## Description\n\n{ticket['description']}\n\n"
        f"## Recommended remediation\n\n{ticket['remediation'] or 'Review and remediate the affected security condition.'}\n\n"
        "_Generated locally by Vulcanary. Source code, evidence, credentials, and absolute paths are excluded._\n"
    )


def ticket_csv(ticket: dict) -> str:
    output = io.StringIO(newline="")
    fields = ["title", "repository", "rule_id", "severity", "category", "scanner", "path", "line", "fingerprint", "owner", "deadline", "remediation"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerow({
        **{field: ticket.get(field) or "" for field in fields},
        "path": ticket["location"]["path"], "line": ticket["location"]["line"],
    })
    return output.getvalue()
