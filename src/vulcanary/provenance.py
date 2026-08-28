from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .version import __version__


def scan_provenance(repository_name: str, artifacts: list[Path], ruleset_digest: str) -> dict:
    subjects = []
    for artifact in artifacts:
        if not artifact.is_file():
            continue
        subjects.append({
            "name": artifact.name,
            "digest": {"sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
        })
    subjects.sort(key=lambda item: item["name"])
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://github.com/JesseS69/vulcanary/attestation/scan/v1",
        "predicate": {
            "repository": repository_name,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "scanner": {"name": "Vulcanary", "version": __version__, "rulesetDigest": ruleset_digest},
            "unsigned": True,
            "signing": "Attach a trusted CI identity or key-backed signature outside Vulcanary before treating this statement as an attestation.",
        },
    }


def write_provenance(document: dict, destination: Path) -> None:
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
