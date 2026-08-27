from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from .dependencies import Package
from .version import __version__


def _purl(package: Package) -> str:
    package_type = "npm" if package.ecosystem == "npm" else "pypi"
    if package_type == "npm" and package.name.startswith("@") and "/" in package.name:
        namespace, name = package.name.split("/", 1)
        encoded_name = f"{quote(namespace, safe='')}/{quote(name, safe='')}"
    else:
        encoded_name = quote(package.name, safe="")
    return f"pkg:{package_type}/{encoded_name}@{quote(package.version, safe='')}"


def cyclonedx_document(repository_name: str, packages: list[Package], findings: list[dict]) -> dict:
    grouped: dict[str, dict] = {}
    for package in packages:
        reference = _purl(package)
        item = grouped.setdefault(reference, {
            "type": "library",
            "bom-ref": reference,
            "name": package.name,
            "version": package.version,
            "purl": reference,
            "properties": [],
            "_direct": False,
            "_managers": set(),
        })
        item["_direct"] = item["_direct"] or package.direct
        item["_managers"].add(package.manager)
    components = []
    for item in grouped.values():
        item["properties"] = [
            {"name": "vulcanary:dependency:direct", "value": str(item.pop("_direct")).lower()},
            {"name": "vulcanary:dependency:managers", "value": ",".join(sorted(item.pop("_managers")))},
        ]
        components.append(item)
    components.sort(key=lambda item: (item["name"].lower(), item["version"]))

    vulnerabilities = []
    for finding in findings:
        if finding.get("category") != "dependency":
            continue
        metadata = finding.get("metadata", {})
        package = Package(
            str(metadata.get("package", "")), str(metadata.get("current_version", "")),
            str(metadata.get("ecosystem", "npm")), "", bool(metadata.get("direct")), str(metadata.get("manager", "npm")),
        )
        reference = _purl(package)
        if reference not in grouped:
            continue
        severity = str(finding.get("severity", "high"))
        vulnerabilities.append({
            "id": str(metadata.get("advisory") or finding.get("rule_id", "unknown")),
            "source": {"name": "OSV", "url": "https://osv.dev"},
            "ratings": [{"severity": severity}],
            "description": str(finding.get("title", "Dependency vulnerability")),
            "recommendation": str(finding.get("remediation", "Review the advisory and upgrade to a fixed release.")),
            "affects": [{"ref": reference}],
            "properties": [{"name": "vulcanary:reachability", "value": str(metadata.get("reachability", {}).get("status", "unknown"))}],
        })

    root_reference = f"urn:vulcanary:repository:{quote(repository_name, safe='')}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "Vulcanary", "version": __version__}]},
            "component": {"type": "application", "bom-ref": root_reference, "name": repository_name},
        },
        "components": components,
        "dependencies": [{"ref": root_reference, "dependsOn": sorted(item["bom-ref"] for item in components if any(prop["name"] == "vulcanary:dependency:direct" and prop["value"] == "true" for prop in item["properties"]))}],
        "vulnerabilities": vulnerabilities,
    }


def write_cyclonedx(document: dict, destination: Path) -> None:
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
