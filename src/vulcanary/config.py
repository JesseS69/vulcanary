from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Severity


DEFAULT_EXCLUDES = [
    ".git/**", ".venv/**", "venv/**", "node_modules/**", ".pnpm-store/**", ".expo/**",
    ".vercel/**", "dist/**", "build/**",
    "*.min.js", "*.map", "coverage/**", ".pytest_cache/**",
]


@dataclass
class Config:
    fail_on: Severity = Severity.HIGH
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    ignored_rules: set[str] = field(default_factory=set)
    ignored_fingerprints: set[str] = field(default_factory=set)
    max_file_bytes: int = 1_000_000
    verify_commands: list[list[str]] = field(default_factory=list)
    verify_timeout_seconds: int = 300

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
        return cls(
            fail_on=Severity.parse(data.get("fail_on", "high")),
            exclude=DEFAULT_EXCLUDES + list(data.get("exclude", [])),
            ignored_rules=set(data.get("ignored_rules", [])),
            ignored_fingerprints=set(data.get("ignored_fingerprints", [])),
            max_file_bytes=int(data.get("max_file_bytes", 1_000_000)),
            verify_commands=commands,
            verify_timeout_seconds=max(1, min(int(data.get("verify_timeout_seconds", 300)), 1800)),
        )
