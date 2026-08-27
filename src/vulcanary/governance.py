from __future__ import annotations

from datetime import date

from .config import Config
from .models import Finding, Severity


def suppression_findings(config: Config, today: date | None = None) -> list[Finding]:
    findings = []
    for suppression in config.suppressions:
        if suppression.status(today) != "expired":
            continue
        findings.append(Finding(
            "GOV-SUPPRESSION-EXPIRED", "Security exception has expired",
            f"The {suppression.reason.replace('_', ' ')} exception owned by {suppression.owner} expired on {suppression.expires.isoformat()}.",
            Severity.HIGH, "governance", ".vulcanary.json", 1, suppression.fingerprint,
            "Remove the exception, remediate the underlying finding, or approve a new time-bounded exception after review.",
            "vulcanary-governance", {
                "suppressed_fingerprint": suppression.fingerprint, "reason": suppression.reason,
                "owner": suppression.owner, "expires": suppression.expires.isoformat(), "status": "expired",
            },
        ))
    for fingerprint in sorted(config.ignored_fingerprints):
        findings.append(Finding(
            "GOV-LEGACY-SUPPRESSION", "Unmanaged legacy suppression",
            "This fingerprint is suppressed without an owner, justification, or expiration date.",
            Severity.MEDIUM, "governance", ".vulcanary.json", 1, fingerprint,
            "Replace ignored_fingerprints with a structured, time-bounded suppressions entry.",
            "vulcanary-governance", {"suppressed_fingerprint": fingerprint, "status": "legacy"},
        ))
    for rule in sorted(config.ignored_rules):
        findings.append(Finding(
            "GOV-LEGACY-RULE-IGNORE", "Unmanaged blanket rule suppression",
            f"Security rule {rule} is disabled repository-wide without an owner, justification, or expiration date.",
            Severity.MEDIUM, "governance", ".vulcanary.json", 1, rule,
            "Remove the blanket ignored_rules entry and use reviewed fingerprint-scoped suppressions for confirmed findings.",
            "vulcanary-governance", {"ignored_rule": rule, "status": "legacy"},
        ))
    return findings
