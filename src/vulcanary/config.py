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
    max_file_bytes: int = 1_000_000

    @classmethod
    def load(cls, root: Path, explicit: Path | None = None) -> "Config":
        path = explicit or root / ".vulcanary.json"
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            fail_on=Severity.parse(data.get("fail_on", "high")),
            exclude=DEFAULT_EXCLUDES + list(data.get("exclude", [])),
            ignored_rules=set(data.get("ignored_rules", [])),
            max_file_bytes=int(data.get("max_file_bytes", 1_000_000)),
        )
