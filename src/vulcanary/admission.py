from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .dependencies import Package, discover_packages
from .models import Finding, Severity, relative_path


@dataclass(frozen=True)
class DependencyPolicy:
    deny_packages: frozenset[str] = frozenset()
    deny_licenses: frozenset[str] = frozenset()
    allow_install_scripts: bool = True
    allow_non_registry_sources: bool = False
    require_npm_integrity: bool = True


def load_dependency_policy(root: Path) -> DependencyPolicy:
    path = root / ".vulcanary.json"
    if not path.exists():
        return DependencyPolicy()
    document = json.loads(path.read_text(encoding="utf-8"))
    raw = document.get("dependency_policy", {})
    if not isinstance(raw, dict):
        raise ValueError("dependency_policy must be an object")
    allowed = {"deny_packages", "deny_licenses", "allow_install_scripts", "allow_non_registry_sources", "require_npm_integrity"}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"dependency_policy contains unsupported field: {sorted(unknown)[0]}")
    lists = {}
    for name in ("deny_packages", "deny_licenses"):
        value = raw.get(name, [])
        if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError(f"dependency_policy.{name} must be an array of non-empty strings")
        lists[name] = frozenset(item.strip().lower() for item in value)
    booleans = {}
    for name, default in (("allow_install_scripts", True), ("allow_non_registry_sources", False), ("require_npm_integrity", True)):
        value = raw.get(name, default)
        if not isinstance(value, bool):
            raise ValueError(f"dependency_policy.{name} must be true or false")
        booleans[name] = value
    return DependencyPolicy(**lists, **booleans)


def _identity(package: Package) -> tuple[str, str, str]:
    return package.ecosystem.lower(), package.name.lower(), package.version


def _npm_metadata(root: Path) -> dict[tuple[str, str], dict]:
    result: dict[tuple[str, str], dict] = {}
    for lock in root.rglob("package-lock.json"):
        if any(part in {"node_modules", ".git", "dist", "build"} for part in lock.parts):
            continue
        try:
            document = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for key, value in document.get("packages", {}).items():
            if not key.startswith("node_modules/") or not isinstance(value, dict):
                continue
            name = key.rsplit("node_modules/", 1)[-1].lower()
            version = value.get("version")
            if isinstance(version, str):
                result[(name, version)] = {**value, "lockfile": relative_path(lock, root)}
    return result


def review_dependency_changes(root: Path, base: Path) -> tuple[list[Finding], list[Package]]:
    # The candidate checkout is untrusted and must not be able to weaken the policy evaluating it.
    policy = load_dependency_policy(base)
    current = discover_packages(root)
    previous = {_identity(package) for package in discover_packages(base)}
    added = [package for package in current if _identity(package) not in previous]
    metadata = _npm_metadata(root)
    findings: list[Finding] = []
    for package in added:
        details = metadata.get((package.name.lower(), package.version), {})
        common = {"package": package.name, "version": package.version, "ecosystem": package.ecosystem, "direct": package.direct, "change": "added"}
        if package.name.lower() in policy.deny_packages:
            findings.append(Finding("ADMISSION-DENIED-PACKAGE", "Denied dependency introduced", f"{package.name} is prohibited by repository policy.", Severity.HIGH, "dependency-policy", package.path, 1, f"{package.name}@{package.version}", "Remove the dependency or obtain an explicit, governed policy exception.", "admission", common))
        license_name = str(details.get("license") or "").lower()
        if license_name and license_name in policy.deny_licenses:
            findings.append(Finding("ADMISSION-DENIED-LICENSE", "Dependency with denied license introduced", f"{package.name} declares the denied {details['license']} license.", Severity.HIGH, "license", package.path, 1, f"{package.name}@{package.version}", "Choose a dependency with an approved license or update the reviewed license policy.", "admission", {**common, "license": details["license"]}))
        if details.get("hasInstallScript") is True and not policy.allow_install_scripts:
            findings.append(Finding("ADMISSION-INSTALL-SCRIPT", "Dependency executes an install script", f"{package.name} declares an install-time lifecycle script.", Severity.HIGH, "supply-chain", package.path, 1, f"{package.name}@{package.version}", "Review the package and script in isolation before allowing it.", "admission", common))
        resolved = str(details.get("resolved") or "")
        scheme = urlparse(resolved).scheme.lower()
        source_host = (urlparse(resolved).hostname or "").lower()
        non_registry = bool(resolved) and (
            scheme in {"git", "git+ssh", "git+https", "http", "file"}
            or source_host in {"github.com", "gitlab.com", "bitbucket.org"}
            or resolved.startswith(("github:", "gitlab:", "file:", "../", "./"))
        )
        if non_registry and not policy.allow_non_registry_sources:
            findings.append(Finding("ADMISSION-NONREGISTRY-SOURCE", "Dependency bypasses the package registry", f"{package.name} resolves from a non-registry source.", Severity.HIGH, "supply-chain", package.path, 1, f"{package.name}@{package.version}", "Use a reviewed registry release pinned by the lockfile, or explicitly approve the source.", "admission", common))
        if package.ecosystem.lower() == "npm" and policy.require_npm_integrity and details and not details.get("integrity") and not non_registry:
            findings.append(Finding("ADMISSION-MISSING-INTEGRITY", "New npm dependency lacks an integrity digest", f"{package.name} has no integrity field in the lockfile.", Severity.HIGH, "supply-chain", package.path, 1, f"{package.name}@{package.version}", "Regenerate the lockfile with a supported package manager and verify the registry source.", "admission", common))
    unique = {finding.fingerprint: finding for finding in findings}
    return sorted(unique.values(), key=lambda finding: (-int(finding.severity), finding.path, finding.rule_id)), added
