from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from .config import Config
from .models import Finding, Severity, relative_path


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    category: str
    remediation: str
    extensions: frozenset[str] = frozenset()


RULES = [
    Rule("SECRET-AWS-KEY", "AWS access key in source", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), Severity.CRITICAL, "secret", "Revoke the key, remove it from history, and use a secret manager."),
    Rule("SECRET-PRIVATE-KEY", "Private key in source", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL, "secret", "Remove and rotate the key; load it from a managed secret store."),
    Rule("SECRET-GITHUB-TOKEN", "GitHub token in source", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{30,255}\b"), Severity.CRITICAL, "secret", "Revoke the token and replace it with a short-lived credential."),
    Rule("CODE-PY-EVAL", "Dynamic Python eval", re.compile(r"(?<![\w.])eval\s*\("), Severity.HIGH, "sast", "Avoid eval; parse and validate structured input explicitly.", frozenset({".py"})),
    Rule("CODE-PY-SHELL", "Shell command execution enabled", re.compile(r"subprocess\.(?:run|Popen|call)\s*\([^\n]*shell\s*=\s*True"), Severity.HIGH, "sast", "Pass an argument list with shell=False and validate all user-controlled values.", frozenset({".py"})),
    Rule("CODE-PY-PICKLE", "Unsafe Python deserialization", re.compile(r"(?<![\w.])pickle\.(?:load|loads)\s*\("), Severity.HIGH, "sast", "Do not deserialize untrusted pickle data; use a constrained data format such as JSON and validate its schema.", frozenset({".py"})),
    Rule("CODE-JS-EVAL", "Dynamic JavaScript eval", re.compile(r"(?<![\w.])eval\s*\("), Severity.HIGH, "sast", "Avoid eval and use a safe parser for the expected input format.", frozenset({".js", ".jsx", ".ts", ".tsx"})),
    Rule("CODE-JS-INNERHTML", "Potential DOM XSS sink", re.compile(r"\.innerHTML\s*="), Severity.MEDIUM, "sast", "Use textContent or sanitize trusted HTML with a maintained sanitizer.", frozenset({".js", ".jsx", ".ts", ".tsx"})),
    Rule("IAC-DOCKER-ROOT", "Container runs as root", re.compile(r"^\s*USER\s+(?:root|0)\s*$", re.I | re.M), Severity.MEDIUM, "iac", "Create and switch to an unprivileged user."),
    Rule("IAC-DOCKER-LATEST", "Container base image uses the latest tag", re.compile(r"^\s*FROM\s+\S+:latest(?:\s|$)", re.I | re.M), Severity.MEDIUM, "iac", "Pin the base image to a reviewed immutable digest or explicit version tag."),
    Rule("IAC-DOCKER-CURL-PIPE", "Container build pipes a download to a shell", re.compile(r"^\s*RUN\s+[^\n]*(?:curl|wget)[^\n]*\|\s*(?:sh|bash)\b", re.I | re.M), Severity.HIGH, "iac", "Download a pinned artifact, verify its checksum or signature, and execute it as a separate build step."),
    Rule("IAC-TF-PUBLIC-INGRESS", "Terraform allows ingress from the internet", re.compile(r'cidr_blocks\s*=\s*\[[^\]]*["\']0\.0\.0\.0/0["\']'), Severity.HIGH, "iac", "Restrict ingress CIDRs and ports to required sources."),
    Rule("IAC-TF-PUBLIC-ACL", "Terraform configures a public object-storage ACL", re.compile(r'\bacl\s*=\s*["\']public-(?:read|read-write)["\']'), Severity.HIGH, "iac", "Use a private ACL and grant narrowly scoped access through an explicit policy."),
    Rule("CI-GHA-WRITE-ALL", "GitHub Actions grants write-all permissions", re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.I | re.M), Severity.HIGH, "ci", "Declare the minimum required permissions and default unspecified scopes to none."),
]


def ruleset_manifest() -> dict:
    rules = [{
        "id": rule.id, "title": rule.title, "severity": rule.severity.name.lower(),
        "category": rule.category, "extensions": sorted(rule.extensions), "remediation": rule.remediation,
    } for rule in sorted(RULES, key=lambda item: item.id)]
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()
    return {"version": 1, "algorithm": "sha256", "digest": hashlib.sha256(canonical).hexdigest(), "rules": rules}


def ruleset_digest() -> str:
    return ruleset_manifest()["digest"]

INLINE_IGNORE_PATTERN = re.compile(
    r"^\s*(?://|#|<!--)\s*vulcanary:ignore\s+(?P<rule>[A-Z0-9-]+)\s+owner=(?P<owner>\S+)\s+expires=(?P<expires>\d{4}-\d{2}-\d{2})\s+--\s+(?P<justification>.+?)(?:\s*-->)?$"
)
INLINE_IGNORE_MARKER = re.compile(r"^\s*(?://|#|<!--)\s*vulcanary:ignore\b")


@dataclass(frozen=True)
class InlineSuppression:
    rule_id: str
    owner: str
    justification: str
    expires: str | None
    path: str
    line: int
    status: str
    error: str | None = None

    @property
    def fingerprint(self) -> str:
        value = f"inline\0{self.path}\0{self.line}\0{self.rule_id}".encode()
        return hashlib.sha256(value).hexdigest()[:20]

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint, "reason": "inline_ignore", "owner": self.owner,
            "justification": self.justification, "expires": self.expires, "status": self.status,
            "scope": "inline", "rule_id": self.rule_id, "path": self.path, "line": self.line,
        }


def _parse_inline_suppression(line_text: str, path: str, line: int, today: date | None = None) -> InlineSuppression | None:
    if not INLINE_IGNORE_MARKER.search(line_text):
        return None
    match = INLINE_IGNORE_PATTERN.search(line_text.strip())
    if not match:
        return InlineSuppression("unknown", "unmanaged", "Invalid inline exception annotation.", None, path, line, "invalid", "Required format is incomplete")
    values = match.groupdict()
    owner = values["owner"].strip()
    justification = values["justification"].strip()
    if len(owner) < 2 or len(justification) < 10:
        return InlineSuppression(values["rule"], owner or "unmanaged", justification or "Missing justification.", values["expires"], path, line, "invalid", "Owner and a justification of at least 10 characters are required")
    try:
        expiry = date.fromisoformat(values["expires"])
    except ValueError:
        return InlineSuppression(values["rule"], owner, justification, values["expires"], path, line, "invalid", "Expiration must be a valid ISO date")
    current = today or date.today()
    status = "expired" if expiry < current else "expiring" if (expiry - current).days <= 14 else "active"
    return InlineSuppression(values["rule"], owner, justification, values["expires"], path, line, status)


def _supports_inline_suppressions(path: Path) -> bool:
    return path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".tf"} or path.name.lower() in {"dockerfile", "containerfile"}


def inline_suppression_register(root: Path, config: Config, today: date | None = None) -> list[dict]:
    records = []
    for path in iter_files(root, config):
        if not _supports_inline_suppressions(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = relative_path(path, root)
        records.extend(record.to_dict() for number, text in enumerate(lines, 1) if (record := _parse_inline_suppression(text, rel, number, today)))
    return records


def iter_files(root: Path, config: Config) -> Iterable[Path]:
    def excluded(path: Path) -> bool:
        rel = relative_path(path, root)
        return any(
            fnmatch.fnmatch(rel, pattern)
            or fnmatch.fnmatch(rel, f"*/{pattern}")
            or fnmatch.fnmatch(f"{rel}/", pattern)
            or fnmatch.fnmatch(f"{rel}/", f"*/{pattern}")
            or fnmatch.fnmatch(path.name, pattern)
            for pattern in config.exclude
        )

    for directory, names, files in os.walk(root, topdown=True):
        parent = Path(directory)
        names[:] = [name for name in names if not excluded(parent / name)]
        for name in files:
            path = parent / name
            if excluded(path):
                continue
            try:
                if path.stat().st_size > config.max_file_bytes:
                    continue
            except OSError:
                continue
            yield path


def scan(root: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root, config):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = relative_path(path, root)
        lines = text.splitlines()
        annotations = {
            number: record for number, line_text in enumerate(lines, 1)
            if (record := _parse_inline_suppression(line_text, rel, number))
        } if _supports_inline_suppressions(path) else {}
        for record in annotations.values():
            if record.status not in {"invalid", "expired", "expiring"}:
                continue
            severity = Severity.HIGH if record.status in {"invalid", "expired"} else Severity.MEDIUM
            title = {"invalid": "Invalid inline security exception", "expired": "Inline security exception has expired", "expiring": "Inline security exception expires soon"}[record.status]
            findings.append(Finding(
                f"GOV-INLINE-IGNORE-{record.status.upper()}", title,
                record.error or f"The inline exception for {record.rule_id} is {record.status}.", severity,
                "governance", rel, record.line, record.rule_id,
                "Complete or renew the exception after review, or remediate the underlying finding.",
                "vulcanary-governance", record.to_dict(),
            ))
        for rule in RULES:
            if rule.id in config.ignored_rules:
                continue
            if rule.extensions and path.suffix.lower() not in rule.extensions:
                continue
            if rule.id.startswith("IAC-DOCKER-") and path.name.lower() not in {"dockerfile", "containerfile"}:
                continue
            if rule.id.startswith("IAC-TF-") and path.suffix.lower() != ".tf":
                continue
            if rule.id.startswith("CI-GHA-") and not (path.suffix.lower() in {".yml", ".yaml"} and ".github/workflows/" in f"/{rel}"):
                continue
            for match in rule.pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                candidates = [annotations[number] for number in (line - 1, line) if number in annotations]
                if any(record.rule_id == rule.id and record.status in {"active", "expiring"} for record in candidates):
                    continue
                evidence = match.group(0).replace("\n", " ")[:120]
                if rule.category == "secret":
                    evidence = "[redacted]"
                finding = Finding(rule.id, rule.title, f"Matched security rule {rule.id}.", rule.severity, rule.category, rel, line, evidence, rule.remediation)
                if not config.is_suppressed(finding.fingerprint):
                    findings.append(finding)
    return sorted({item.fingerprint: item for item in findings}.values(), key=lambda f: (-int(f.severity), f.path, f.line))
