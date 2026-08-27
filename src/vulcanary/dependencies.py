from __future__ import annotations

import json
import hashlib
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from .models import Finding, Severity, relative_path
from .version import __version__


_CACHE_TTL_SECONDS = 6 * 60 * 60


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str
    path: str
    direct: bool = False
    manager: str = "npm"


_SKIPPED_PARTS = {"node_modules", ".git", ".expo", ".pnpm-store", ".venv", "venv", ".vercel", "dist", "build", "coverage"}


def _dependency_files(root: Path, accepted: Callable[[str], bool]) -> list[Path]:
    found = []
    for directory, names, files in os.walk(root, topdown=True):
        names[:] = [name for name in names if name not in _SKIPPED_PARTS]
        parent = Path(directory)
        found.extend(parent / name for name in files if accepted(name))
    return found


def _declared_names(directory: Path) -> set[str]:
    try:
        package = json.loads((directory / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return set(package.get("dependencies", {})) | set(package.get("devDependencies", {}))


def _yarn_packages(lock: Path, root: Path) -> list[Package]:
    direct = _declared_names(lock.parent)
    found = []
    header: str | None = None
    for raw in lock.read_text(encoding="utf-8").splitlines():
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            header = raw.strip().rstrip(":").strip('"')
            continue
        version = re.match(r'^\s+version\s*:?[ ]*["\']?([^"\'\s]+)', raw)
        if not header or not version:
            continue
        selector = header.split(",", 1)[0].strip().strip('"')
        match = re.match(r"(?P<name>@[^/]+/[^@]+|[^@]+)@(?:npm:)?", selector)
        if match:
            name = match.group("name")
            found.append(Package(name, version.group(1), "npm", relative_path(lock, root), name in direct, "yarn"))
        header = None
    return found


def _pnpm_packages(lock: Path, root: Path) -> list[Package]:
    direct = _declared_names(lock.parent)
    found = []
    in_packages = False
    for raw in lock.read_text(encoding="utf-8").splitlines():
        if raw == "packages:":
            in_packages = True
            continue
        if in_packages and raw and not raw[0].isspace():
            break
        if not in_packages:
            continue
        match = re.match(r"^\s{2}['\"]?(.+?)['\"]?:\s*$", raw)
        if not match:
            continue
        key = match.group(1).lstrip("/").split("(", 1)[0]
        split = key.rfind("@")
        if split <= 0:
            continue
        name, version = key[:split], key[split + 1:]
        if name and re.match(r"^\d+\.\d+\.\d+", version):
            found.append(Package(name, version, "npm", relative_path(lock, root), name in direct, "pnpm"))
    return found


def discover_packages(root: Path) -> list[Package]:
    packages: dict[tuple[str, str, str, str], Package] = {}
    for lock in _dependency_files(root, lambda name: name == "package-lock.json"):
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
                packages[(package.ecosystem, name, version, package.path)] = package
    for pattern, reader in (("yarn.lock", _yarn_packages), ("pnpm-lock.yaml", _pnpm_packages)):
        for lock in _dependency_files(root, lambda name, expected=pattern: name == expected):
            try:
                discovered = reader(lock, root)
            except OSError:
                continue
            for package in discovered:
                packages[(package.ecosystem, package.name, package.version, package.path)] = package
    requirement = re.compile(r"^\s*([A-Za-z0-9_.-]+)==([^\s;]+)")
    for lock in _dependency_files(root, lambda name: name.startswith("requirements") and name.endswith(".txt")):
        try:
            lines = lock.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            match = requirement.match(line)
            if match:
                package = Package(match.group(1), match.group(2), "PyPI", relative_path(lock, root), True, "pip")
                packages[(package.ecosystem, package.name.lower(), package.version, package.path)] = package
    return list(packages.values())


def _json_request(url: str, payload: dict | None = None, timeout: float = 10) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": f"Vulcanary/{__version__}"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _cache_directory(configured: Path | bool | None) -> Path | None:
    if configured is False:
        return None
    if isinstance(configured, Path):
        return configured
    override = os.environ.get("VULCANARY_CACHE_DIR")
    return Path(override) if override else Path(tempfile.gettempdir()) / "vulcanary-osv-cache"


def _cache_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _cache_read(directory: Path | None, namespace: str, key: str) -> dict | None:
    if directory is None:
        return None
    path = directory / namespace / f"{_cache_key(key)}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - float(payload["stored_at"]) <= _CACHE_TTL_SECONDS and isinstance(payload["value"], dict):
            return payload["value"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return None


def _cache_write(directory: Path | None, namespace: str, key: str, value: dict) -> None:
    if directory is None:
        return
    target = directory / namespace / f"{_cache_key(key)}.json"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(f".{os.getpid()}.tmp")
        temporary.write_text(json.dumps({"stored_at": time.time(), "value": value}), encoding="utf-8")
        temporary.replace(target)
    except OSError:
        pass


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


def scan_dependencies(root: Path, timeout: float = 10, cache_dir: Path | bool | None = None) -> tuple[list[Finding], str | None]:
    packages = discover_packages(root)
    if not packages:
        return [], None
    cache = _cache_directory(cache_dir)
    results: list[dict | None] = []
    missing: list[tuple[int, Package, str]] = []
    for index, package in enumerate(packages):
        identity = f"{package.ecosystem}\0{package.name}\0{package.version}"
        cached = _cache_read(cache, "queries", identity)
        results.append(cached)
        if cached is None:
            missing.append((index, package, identity))
    try:
        if missing:
            queries = [{"package": {"name": package.name, "ecosystem": package.ecosystem}, "version": package.version} for _, package, _ in missing]
            batch = _json_request("https://api.osv.dev/v1/querybatch", {"queries": queries}, timeout)
            fetched = batch.get("results", [])
            for offset, (index, _, identity) in enumerate(missing):
                result = fetched[offset] if offset < len(fetched) and isinstance(fetched[offset], dict) else {}
                results[index] = result
                _cache_write(cache, "queries", identity, result)
        normalized_results = [result or {} for result in results]
        advisory_ids = {item["id"] for result in normalized_results for item in result.get("vulns", [])}
        records = {}
        for advisory_id in advisory_ids:
            record = _cache_read(cache, "advisories", advisory_id)
            if record is None:
                record = _json_request(f"https://api.osv.dev/v1/vulns/{advisory_id}", timeout=timeout)
                _cache_write(cache, "advisories", advisory_id, record)
            records[advisory_id] = record
    except (OSError, URLError, ValueError, json.JSONDecodeError) as error:
        return [], f"OSV dependency scan unavailable: {error}"
    findings = []
    for package, result in zip(packages, normalized_results):
        for summary in result.get("vulns", []):
            record = records.get(summary["id"], {})
            fixed = _fixed_version(record, package)
            same_major = _same_major(package.version, fixed)
            parent_packages = direct_parent_packages(root, package) if package.manager == "npm" and not package.direct else []
            fix_eligible = bool(package.manager == "npm" and package.direct and same_major)
            if package.ecosystem != "npm":
                fix_block_reason = f"Automatic upgrades do not yet support {package.ecosystem}"
            elif package.manager != "npm":
                fix_block_reason = f"Vulcanary scans {package.manager} locks read-only; automatic upgrades are not enabled yet"
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
                    "manager": package.manager,
                    "direct": package.direct,
                    "fix_eligible": fix_eligible,
                    "fix_block_reason": fix_block_reason,
                    "parent_packages": parent_packages,
                    "fix_strategy": "dependency" if package.direct else "override",
                    "advisory": summary["id"],
                },
            ))
    return findings, None
