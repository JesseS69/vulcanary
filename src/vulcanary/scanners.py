from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
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
    Rule("CODE-JS-EVAL", "Dynamic JavaScript eval", re.compile(r"(?<![\w.])eval\s*\("), Severity.HIGH, "sast", "Avoid eval and use a safe parser for the expected input format.", frozenset({".js", ".jsx", ".ts", ".tsx"})),
    Rule("CODE-JS-INNERHTML", "Potential DOM XSS sink", re.compile(r"\.innerHTML\s*="), Severity.MEDIUM, "sast", "Use textContent or sanitize trusted HTML with a maintained sanitizer.", frozenset({".js", ".jsx", ".ts", ".tsx"})),
    Rule("IAC-DOCKER-ROOT", "Container runs as root", re.compile(r"^\s*USER\s+(?:root|0)\s*$", re.I | re.M), Severity.MEDIUM, "iac", "Create and switch to an unprivileged user."),
    Rule("IAC-TF-PUBLIC-INGRESS", "Terraform allows ingress from the internet", re.compile(r'cidr_blocks\s*=\s*\[[^\]]*["\']0\.0\.0\.0/0["\']'), Severity.HIGH, "iac", "Restrict ingress CIDRs and ports to required sources."),
]


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
        for rule in RULES:
            if rule.id in config.ignored_rules:
                continue
            if rule.extensions and path.suffix.lower() not in rule.extensions:
                continue
            if rule.id == "IAC-DOCKER-ROOT" and path.name.lower() not in {"dockerfile", "containerfile"}:
                continue
            if rule.id == "IAC-TF-PUBLIC-INGRESS" and path.suffix.lower() != ".tf":
                continue
            for match in rule.pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                evidence = match.group(0).replace("\n", " ")[:120]
                if rule.category == "secret":
                    evidence = "[redacted]"
                findings.append(Finding(rule.id, rule.title, f"Matched security rule {rule.id}.", rule.severity, rule.category, rel, line, evidence, rule.remediation))
    return sorted({item.fingerprint: item for item in findings}.values(), key=lambda f: (-int(f.severity), f.path, f.line))
