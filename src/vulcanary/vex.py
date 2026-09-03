from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .dependencies import Package
from .sbom import package_url
from .version import __version__


def _purl(metadata: dict) -> str | None:
    name, version = str(metadata.get("package") or ""), str(metadata.get("current_version") or "")
    if not name or not version:
        return None
    try:
        return package_url(Package(name, version, str(metadata.get("ecosystem", "npm")), ""))
    except ValueError:
        return None


def openvex_document(repository_name: str, findings: list[dict]) -> dict:
    statements = []
    seen = set()
    for finding in findings:
        if finding.get("category") != "dependency":
            continue
        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        advisory = str(metadata.get("advisory") or finding.get("rule_id") or "")
        product = _purl(metadata)
        if not advisory or not product or (advisory, product) in seen:
            continue
        seen.add((advisory, product))
        statements.append({
            "vulnerability": {"name": advisory}, "products": [{"@id": product}], "status": "affected",
            "status_notes": "Vulcanary observed the vulnerable version in the dependency inventory. Reachability context does not prove safety.",
        })
    return {
        "@context": "https://openvex.dev/ns/v0.2.0", "@id": f"https://github.com/JesseS69/vulcanary/vex/{uuid4()}",
        "author": "Vulcanary local scanner", "role": "Document Creator", "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1, "tooling": f"Vulcanary {__version__}", "product": repository_name, "statements": statements,
    }


def write_openvex(document: dict, destination: Path) -> None:
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
