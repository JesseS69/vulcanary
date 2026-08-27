from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .models import Severity


DEFAULT_EXCLUDES = [
    ".git/**", ".venv/**", "venv/**", "node_modules/**", ".pnpm-store/**", ".expo/**",
    ".vercel/**", "dist/**", "build/**",
    "*.min.js", "*.map", "coverage/**", ".pytest_cache/**",
]
SUPPRESSION_REASONS = {"false_positive", "mitigated", "accepted_risk", "deferred"}


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    owner: str
    justification: str
    expires: date

    def status(self, today: date | None = None) -> str:
        current = today or date.today()
        if self.expires < current:
            return "expired"
        if (self.expires - current).days <= 14:
            return "expiring"
        return "active"

    def to_dict(self, today: date | None = None) -> dict:
        return {
            "fingerprint": self.fingerprint, "reason": self.reason, "owner": self.owner,
            "justification": self.justification, "expires": self.expires.isoformat(), "status": self.status(today),
        }


@dataclass
class Config:
    fail_on: Severity = Severity.HIGH
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    ignored_rules: set[str] = field(default_factory=set)
    ignored_fingerprints: set[str] = field(default_factory=set)
    suppressions: tuple[Suppression, ...] = ()
    max_file_bytes: int = 1_000_000
    verify_commands: list[list[str]] = field(default_factory=list)
    verify_timeout_seconds: int = 300

    def is_suppressed(self, fingerprint: str, today: date | None = None) -> bool:
        if fingerprint in self.ignored_fingerprints:
            return True
        return any(item.fingerprint == fingerprint and item.status(today) != "expired" for item in self.suppressions)

    def suppression_register(self, today: date | None = None) -> list[dict]:
        return [item.to_dict(today) for item in self.suppressions] + [
            {"fingerprint": fingerprint, "reason": "legacy", "owner": "unmanaged", "justification": "Legacy ignored_fingerprints entry", "expires": None, "status": "legacy", "scope": "fingerprint"}
            for fingerprint in sorted(self.ignored_fingerprints)
        ] + [
            {"fingerprint": f"rule:{rule}", "reason": "legacy", "owner": "unmanaged", "justification": "Legacy ignored_rules entry", "expires": None, "status": "legacy", "scope": "rule"}
            for rule in sorted(self.ignored_rules)
        ]

    @classmethod
    def load(cls, root: Path, explicit: Path | None = None) -> "Config":
        path = explicit or root / ".vulcanary.json"
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        commands = data.get("verify_commands", [])
        if not isinstance(commands, list) or any(
            not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command)
            for command in commands
        ):
            raise ValueError("verify_commands must be an array of non-empty argument arrays")
        suppressions_data = data.get("suppressions", [])
        if not isinstance(suppressions_data, list):
            raise ValueError("suppressions must be an array")
        ignored_fingerprints = data.get("ignored_fingerprints", [])
        if not isinstance(ignored_fingerprints, list) or any(not isinstance(item, str) for item in ignored_fingerprints):
            raise ValueError("ignored_fingerprints must be an array of strings")
        ignored_rules = data.get("ignored_rules", [])
        if not isinstance(ignored_rules, list) or any(not isinstance(item, str) or not item for item in ignored_rules):
            raise ValueError("ignored_rules must be an array of non-empty strings")
        exclusions = data.get("exclude", [])
        if not isinstance(exclusions, list) or any(not isinstance(item, str) or not item for item in exclusions):
            raise ValueError("exclude must be an array of non-empty strings")
        suppressions = []
        fingerprints = set()
        for index, item in enumerate(suppressions_data, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"suppression {index} must be an object")
            fingerprint = item.get("fingerprint")
            reason = item.get("reason")
            owner = item.get("owner")
            justification = item.get("justification")
            expires = item.get("expires")
            if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{20}", fingerprint):
                raise ValueError(f"suppression {index} fingerprint must be a 20-character Vulcanary fingerprint")
            if fingerprint in fingerprints:
                raise ValueError(f"suppression {index} duplicates fingerprint {fingerprint}")
            if reason not in SUPPRESSION_REASONS:
                raise ValueError(f"suppression {index} reason must be one of: {', '.join(sorted(SUPPRESSION_REASONS))}")
            if not isinstance(owner, str) or len(owner.strip()) < 2:
                raise ValueError(f"suppression {index} owner is required")
            if not isinstance(justification, str) or len(justification.strip()) < 10:
                raise ValueError(f"suppression {index} justification must contain at least 10 characters")
            try:
                expiry = date.fromisoformat(expires)
            except (TypeError, ValueError) as error:
                raise ValueError(f"suppression {index} expires must be an ISO date (YYYY-MM-DD)") from error
            fingerprints.add(fingerprint)
            suppressions.append(Suppression(fingerprint, reason, owner.strip(), justification.strip(), expiry))
        overlap = fingerprints & set(ignored_fingerprints)
        if overlap:
            raise ValueError(f"fingerprint {sorted(overlap)[0]} cannot appear in both suppressions and ignored_fingerprints")
        return cls(
            fail_on=Severity.parse(data.get("fail_on", "high")),
            exclude=DEFAULT_EXCLUDES + exclusions,
            ignored_rules=set(ignored_rules),
            ignored_fingerprints=set(ignored_fingerprints),
            suppressions=tuple(suppressions),
            max_file_bytes=int(data.get("max_file_bytes", 1_000_000)),
            verify_commands=commands,
            verify_timeout_seconds=max(1, min(int(data.get("verify_timeout_seconds", 300)), 1800)),
        )
