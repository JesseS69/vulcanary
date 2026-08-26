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


def _resolve_lock_dependency(packages: dict, parent_key: str, dependency: str) -> str | None:
    current = parent_key
    while True:
        candidate = f"{current}/node_modules/{dependency}" if current else f"node_modules/{dependency}"
        if candidate in packages:
            return candidate
        if "/node_modules/" in current:
            current = current.rsplit("/node_modules/", 1)[0]
        elif current:
            current = ""
        else:
            break
    return None


def direct_parent_packages(root: Path, package: Package) -> list[str]:
    lock = root / package.path
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        return []
    root_package = packages.get("", {})
    direct_names = sorted(set(root_package.get("dependencies", {})) | set(root_package.get("devDependencies", {})))
    graph: dict[str, list[str]] = {}
    for key, value in packages.items():
        if not isinstance(value, dict):
            continue
        dependencies = set(value.get("dependencies", {})) | set(value.get("optionalDependencies", {}))
        graph[key] = [resolved for name in dependencies if (resolved := _resolve_lock_dependency(packages, key, name))]

    def contains_target(start: str) -> bool:
        pending = [start]
        visited = set()
        while pending:
            key = pending.pop()
            if key in visited:
                continue
            visited.add(key)
            value = packages.get(key, {})
            name = key.rsplit("node_modules/", 1)[-1]
            if name.lower() == package.name.lower() and value.get("version") == package.version:
                return True
            pending.extend(graph.get(key, []))
        return False

    parents = []
    for name in direct_names:
        key = _resolve_lock_dependency(packages, "", name)
        if key and contains_target(key):
            parents.append(name)
    return parents


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
            same_major = _same_major(package.version, fixed)
            parent_packages = direct_parent_packages(root, package) if package.ecosystem == "npm" and not package.direct else []
            fix_eligible = bool(package.ecosystem == "npm" and package.direct and same_major)
            if package.ecosystem != "npm":
                fix_block_reason = f"Automatic upgrades do not yet support {package.ecosystem}"
            elif not fixed:
                fix_block_reason = "The advisory does not identify a patched release yet"
            elif not same_major:
                fix_block_reason = f"The fix requires a major upgrade to {fixed}"
            elif not package.direct:
                candidates = ", ".join(parent_packages) if parent_packages else "the introducing direct dependency"
                fix_block_reason = f"Upgrade {candidates}; unscoped transitive overrides can break other dependency paths"
            else:
                fix_block_reason = None
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
                    "fix_eligible": fix_eligible,
                    "fix_block_reason": fix_block_reason,
                    "parent_packages": parent_packages,
                    "fix_strategy": "dependency" if package.direct else "override",
                    "advisory": summary["id"],
                },
            ))
    return findings, None
