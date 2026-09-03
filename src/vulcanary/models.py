from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from hashlib import sha256
from pathlib import Path


class Severity(IntEnum):
    UNKNOWN = -1
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.upper()]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: str
    path: str
    line: int
    evidence: str = ""
    remediation: str = ""
    scanner: str = "builtin"
    metadata: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        identity = f"{self.rule_id}\0{self.path}\0{self.line}\0{self.evidence}"
        return sha256(identity.encode()).hexdigest()[:20]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["severity"] = self.severity.name.lower()
        result["fingerprint"] = self.fingerprint
        return result


def relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()
