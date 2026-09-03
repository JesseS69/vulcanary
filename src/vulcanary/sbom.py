from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from .dependencies import Package
from .version import __version__


def package_url(package: Package) -> str:
    package_type = {"npm": "npm", "pypi": "pypi", "go": "golang", "crates.io": "cargo"}.get(package.ecosystem.lower())
    if package_type is None:
        raise ValueError(f"Unsupported package ecosystem: {package.ecosystem}")
    if package_type == "npm" and package.name.startswith("@") and "/" in package.name:
        namespace, name = package.name.split("/", 1)
        encoded_name = f"{quote(namespace, safe='')}/{quote(name, safe='')}"
    elif package_type == "golang":
        encoded_name = "/".join(quote(part, safe="") for part in package.name.split("/"))
    else:
        encoded_name = quote(package.name, safe="")
    return f"pkg:{package_type}/{encoded_name}@{quote(package.version, safe='')}"


_purl = package_url


def inventory_snapshot(packages: list[Package]) -> dict[str, dict]:
    grouped: dict[str, dict] = {}
    for package in packages:
        reference = _purl(package)
        item = grouped.setdefault(reference, {
            "name": package.name,
            "version": package.version,
            "ecosystem": package.ecosystem,
            "direct": False,
            "managers": [],
        })
        item["direct"] = item["direct"] or package.direct
        item["managers"] = sorted(set(item["managers"]) | {package.manager})
    return dict(sorted(grouped.items()))


def cyclonedx_document(repository_name: str, packages: list[Package], findings: list[dict]) -> dict:
    grouped = inventory_snapshot(packages)
    components = []
    for reference, inventory in grouped.items():
        components.append({
            "type": "library", "bom-ref": reference, "name": inventory["name"],
            "version": inventory["version"], "purl": reference,
            "properties": [
                {"name": "vulcanary:dependency:direct", "value": str(inventory["direct"]).lower()},
                {"name": "vulcanary:dependency:managers", "value": ",".join(inventory["managers"])},
            ],
        })
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


def spdx_document(repository_name: str, packages: list[Package], findings: list[dict]) -> dict:
    grouped = inventory_snapshot(packages)
    root_id = "SPDXRef-Repository"
    advisory_by_ref: dict[str, list[str]] = {}
    for finding in findings:
        if finding.get("category") != "dependency":
            continue
        metadata = finding.get("metadata", {})
        package = Package(
            str(metadata.get("package", "")), str(metadata.get("current_version", "")),
            str(metadata.get("ecosystem", "npm")), "", bool(metadata.get("direct")), str(metadata.get("manager", "npm")),
        )
        advisory_by_ref.setdefault(_purl(package), []).append(str(metadata.get("advisory") or finding.get("rule_id", "unknown")))
    document_packages = [{
        "SPDXID": root_id, "name": repository_name, "versionInfo": "NOASSERTION",
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
    }]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    for reference, inventory in grouped.items():
        package_id = f"SPDXRef-Package-{hashlib.sha256(reference.encode()).hexdigest()[:16]}"
        item = {
            "SPDXID": package_id, "name": inventory["name"], "versionInfo": inventory["version"],
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": reference}],
            "comment": f"Vulcanary managers: {','.join(inventory['managers'])}; direct: {str(inventory['direct']).lower()}",
        }
        advisories = sorted(set(advisory_by_ref.get(reference, [])))
        if advisories:
            item["annotations"] = [{
                "annotationType": "OTHER", "annotator": f"Tool: Vulcanary-{__version__}",
                "annotationDate": datetime.now(timezone.utc).isoformat(), "comment": f"OSV advisories: {', '.join(advisories)}",
            }]
        document_packages.append(item)
        if inventory["direct"]:
            relationships.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": package_id})
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{repository_name}-vulcanary-sbom",
        "documentNamespace": f"https://vulcanary.dev/spdx/{quote(repository_name, safe='')}/{uuid4()}",
        "creationInfo": {"created": datetime.now(timezone.utc).isoformat(), "creators": [f"Tool: Vulcanary-{__version__}"]},
        "packages": document_packages, "relationships": relationships,
    }


def write_spdx(document: dict, destination: Path) -> None:
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
