from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .models import Finding, Severity, relative_path


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str
    path: str
    direct: bool = False


def discover_packages(root: Path) -> list[Package]:
    packages: dict[tuple[str, str, str], Package] = {}
    for lock in root.rglob("package-lock.json"):
        if {"node_modules", ".git", ".expo", ".pnpm-store", "dist", "build"} & set(lock.parts):
            continue
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        root_package = data.get("packages", {}).get("", {})
        direct_names = set(root_package.get("dependencies", {})) | set(root_package.get("devDependencies", {}))
        for key, value in data.get("packages", {}).items():
            if not key.startswith("node_modules/") or not isinstance(value, dict):
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            version = value.get("version")
            if name and isinstance(version, str):
                package = Package(name, version, "npm", relative_path(lock, root), name in direct_names)
                packages[(package.ecosystem, name, version)] = package
    requirement = re.compile(r"^\s*([A-Za-z0-9_.-]+)==([^\s;]+)")
    for lock in root.rglob("requirements*.txt"):
        if {".git", ".venv", "venv", "build", "dist"} & set(lock.parts):
            continue
        try:
            lines = lock.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            match = requirement.match(line)
            if match:
                package = Package(match.group(1), match.group(2), "PyPI", relative_path(lock, root))
                packages[(package.ecosystem, package.name.lower(), package.version)] = package
    return list(packages.values())


def _json_request(url: str, payload: dict | None = None, timeout: float = 10) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "Vulcanary/0.3"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _severity(record: dict) -> Severity:
    candidates = [record.get("database_specific", {}).get("severity")]
    for affected in record.get("affected", []):
        candidates.append(affected.get("ecosystem_specific", {}).get("severity"))
        candidates.append(affected.get("database_specific", {}).get("severity"))
    values = " ".join(str(item).upper() for item in candidates if item)
    for name in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
        if name in values:
            return Severity.MEDIUM if name == "MODERATE" else Severity[name]
    return Severity.HIGH


def _fixed_version(record: dict, package: Package) -> str | None:
    for affected in record.get("affected", []):
        identity = affected.get("package", {})
        if identity.get("name", "").lower() != package.name.lower():
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                if event.get("fixed"):
                    return event["fixed"]
    return None


def _same_major(current: str, fixed: str | None) -> bool:
    if not fixed:
        return False
    current_major = re.match(r"\D*(\d+)", current)
    fixed_major = re.match(r"\D*(\d+)", fixed)
    return bool(current_major and fixed_major and current_major.group(1) == fixed_major.group(1))


def scan_dependencies(root: Path, timeout: float = 10) -> tuple[list[Finding], str | None]:
    packages = discover_packages(root)
    if not packages:
        return [], None
    queries = [{"package": {"name": package.name, "ecosystem": package.ecosystem}, "version": package.version} for package in packages]
    try:
        batch = _json_request("https://api.osv.dev/v1/querybatch", {"queries": queries}, timeout)
        advisory_ids = {item["id"] for result in batch.get("results", []) for item in result.get("vulns", [])}
        records = {advisory_id: _json_request(f"https://api.osv.dev/v1/vulns/{advisory_id}", timeout=timeout) for advisory_id in advisory_ids}
    except (OSError, URLError, ValueError, json.JSONDecodeError) as error:
        return [], f"OSV dependency scan unavailable: {error}"
    findings = []
    for package, result in zip(packages, batch.get("results", [])):
        for summary in result.get("vulns", []):
            record = records.get(summary["id"], {})
            fixed = _fixed_version(record, package)
            remediation = f"Upgrade {package.name} to {fixed} or later." if fixed else f"Review {summary['id']} and upgrade {package.name} to a non-affected release."
            findings.append(Finding(
                f"SCA-{summary['id']}", record.get("summary") or f"Vulnerable dependency: {package.name}",
                f"{package.name} {package.version} is affected by {summary['id']}.", _severity(record), "dependency",
                package.path, 1, f"{package.name}@{package.version}", remediation, "osv", {
                    "package": package.name,
                    "current_version": package.version,
                    "fixed_version": fixed,
                    "ecosystem": package.ecosystem,
                    "direct": package.direct,
                    "fix_eligible": bool(package.ecosystem == "npm" and _same_major(package.version, fixed)),
                    "fix_strategy": "dependency" if package.direct else "override",
                    "advisory": summary["id"],
                },
            ))
    return findings, None
