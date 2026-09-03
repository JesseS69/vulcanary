from __future__ import annotations

import json
import hashlib
import math
import os
import re
import tempfile
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from .models import Finding, Severity, relative_path
from .version import __version__
from ._vendor.cvss import CVSS4


_CACHE_TTL_SECONDS = 6 * 60 * 60


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str
    path: str
    direct: bool = False
    manager: str = "npm"
    scope: str = "runtime"


_SKIPPED_PARTS = {"node_modules", "vendor", ".bundle", ".git", ".expo", ".pnpm-store", ".uv-cache", ".venv", "venv", ".vercel", "dist", "build", "coverage"}


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


def _python_toml_lock_packages(lock: Path, root: Path, manager: str) -> list[Package]:
    """Read package name/version pairs from Poetry, uv, and PDM TOML lockfiles."""
    found = []
    name: str | None = None
    version: str | None = None
    in_package = False
    for raw in lock.read_text(encoding="utf-8").splitlines() + ["[[package]]"]:
        if raw.strip() == "[[package]]":
            if in_package and name and version:
                found.append(Package(name, version, "PyPI", relative_path(lock, root), False, manager))
            in_package, name, version = True, None, None
            continue
        if not in_package:
            continue
        match = re.match(r'^\s*(name|version)\s*=\s*["\']([^"\']+)["\']\s*$', raw)
        if match:
            if match.group(1) == "name":
                name = match.group(2)
            else:
                version = match.group(2)
    return found


def _cargo_declared_names(directory: Path) -> set[str]:
    """Collect actual crate names declared by manifests governed by one Cargo lock."""
    names = set()
    for manifest in _dependency_files(directory, lambda name: name == "Cargo.toml"):
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue

        def collect(value: dict) -> None:
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                declarations = value.get(key, {})
                if not isinstance(declarations, dict):
                    continue
                for alias, declaration in declarations.items():
                    actual = declaration.get("package", alias) if isinstance(declaration, dict) else alias
                    if isinstance(actual, str):
                        names.add(actual)

        collect(document)
        targets = document.get("target", {})
        if isinstance(targets, dict):
            for target in targets.values():
                if isinstance(target, dict):
                    collect(target)
    return names


def _cargo_packages(lock: Path, root: Path) -> list[Package]:
    try:
        document = tomllib.loads(lock.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    direct = _cargo_declared_names(lock.parent)
    found = []
    for record in document.get("package", []):
        if not isinstance(record, dict):
            continue
        name, version, source = record.get("name"), record.get("version"), record.get("source")
        # No source means a local workspace crate. Git and alternate-registry packages
        # do not have crates.io identities and must not be queried as though they do.
        if not (isinstance(name, str) and isinstance(version, str) and isinstance(source, str)):
            continue
        if not source.startswith("registry+") or "crates.io-index" not in source:
            continue
        found.append(Package(name, version, "crates.io", relative_path(lock, root), name in direct, "cargo"))
    return found


def _go_packages(manifest: Path, root: Path) -> list[Package]:
    """Read resolved module requirements without invoking the Go toolchain."""
    found = []
    in_require = False
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped == "require (":
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if not in_require:
            match = re.match(r"^require\s+(\S+)\s+(v\S+)(?:\s+//\s*(.*))?$", stripped)
        else:
            match = re.match(r"^(\S+)\s+(v\S+)(?:\s+//\s*(.*))?$", stripped)
        if not match:
            continue
        name, version, comment = match.groups()
        if not re.match(r"^v\d", version):
            continue
        found.append(Package(name, version[1:], "Go", relative_path(manifest, root), comment != "indirect", "go"))
    return found


def _composer_packages(lock: Path, root: Path) -> list[Package]:
    try:
        document = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    try:
        manifest = json.loads((lock.parent / "composer.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    runtime_direct = {str(name).lower() for name in manifest.get("require", {}) if name != "php" and not str(name).startswith(("ext-", "lib-"))}
    development_direct = {str(name).lower() for name in manifest.get("require-dev", {})}
    found = []
    for section, scope in (("packages", "runtime"), ("packages-dev", "development")):
        records = document.get(section, [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            name, version = record.get("name"), record.get("version")
            if not isinstance(name, str) or not isinstance(version, str) or "/" not in name:
                continue
            normalized_name = name.lower()
            direct = normalized_name in runtime_direct or normalized_name in development_direct
            found.append(Package(normalized_name, version, "Packagist", relative_path(lock, root), direct, "composer", scope))
    return found


def _nuget_packages(lock: Path, root: Path) -> list[Package]:
    """Read resolved NuGet packages without invoking restore or evaluating project files."""
    try:
        document = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    targets = document.get("dependencies", {})
    if not isinstance(targets, dict):
        return []
    records: dict[tuple[str, str], Package] = {}
    path = relative_path(lock, root)
    for dependencies in targets.values():
        if not isinstance(dependencies, dict):
            continue
        for name, record in dependencies.items():
            if not isinstance(name, str) or not isinstance(record, dict):
                continue
            version, dependency_type = record.get("resolved"), str(record.get("type", "")).lower()
            if not isinstance(version, str) or not version or dependency_type == "project":
                continue
            key = (name.lower(), version)
            direct = dependency_type == "direct"
            previous = records.get(key)
            records[key] = Package(
                previous.name if previous else name, version, "NuGet", path,
                direct or bool(previous and previous.direct), "nuget",
            )
    return list(records.values())


def _gem_packages(lock: Path, root: Path) -> list[Package]:
    lines = lock.read_text(encoding="utf-8").splitlines()
    section = None
    platforms = set()
    direct = set()
    raw_specs: list[tuple[str, str]] = []
    for raw in lines:
        if raw and not raw[0].isspace():
            section = raw.strip()
            continue
        if section == "PLATFORMS":
            match = re.match(r"^\s{2}(\S+)\s*$", raw)
            if match and match.group(1) != "ruby":
                platforms.add(match.group(1))
        elif section == "DEPENDENCIES":
            match = re.match(r"^\s{2}([A-Za-z0-9_.-]+)(?:\s|!|$)", raw)
            if match:
                direct.add(match.group(1))
        elif section == "GEM":
            match = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([^ ()]+)\)\s*$", raw)
            if match:
                raw_specs.append((match.group(1), match.group(2)))
    found = []
    for name, version in raw_specs:
        normalized = version
        for platform_name in sorted(platforms, key=len, reverse=True):
            suffix = f"-{platform_name}"
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)]
                break
        found.append(Package(name, normalized, "RubyGems", relative_path(lock, root), name in direct, "bundler"))
    return found


def _discover_packages(root: Path) -> tuple[list[Package], list[str]]:
    packages: dict[tuple[str, str, str, str], Package] = {}
    unresolved: list[str] = []
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
    for filename, manager in (("poetry.lock", "poetry"), ("uv.lock", "uv"), ("pdm.lock", "pdm")):
        for lock in _dependency_files(root, lambda name, expected=filename: name == expected):
            try:
                discovered = _python_toml_lock_packages(lock, root, manager)
            except OSError:
                continue
            for package in discovered:
                packages[(package.ecosystem, package.name.lower(), package.version, package.path)] = package
    for lock in _dependency_files(root, lambda name: name == "Cargo.lock"):
        for package in _cargo_packages(lock, root):
            packages[(package.ecosystem, package.name, package.version, package.path)] = package
    for manifest in _dependency_files(root, lambda name: name == "go.mod"):
        try:
            discovered = _go_packages(manifest, root)
        except OSError:
            continue
        for package in discovered:
            packages[(package.ecosystem, package.name, package.version, package.path)] = package
    for lock in _dependency_files(root, lambda name: name == "composer.lock"):
        for package in _composer_packages(lock, root):
            packages[(package.ecosystem, package.name, package.version, package.path)] = package
    for lock in _dependency_files(root, lambda name: name == "packages.lock.json"):
        for package in _nuget_packages(lock, root):
            packages[(package.ecosystem, package.name.lower(), package.version, package.path)] = package
    for lock in _dependency_files(root, lambda name: name == "Gemfile.lock"):
        try:
            discovered = _gem_packages(lock, root)
        except OSError:
            continue
        for package in discovered:
            packages[(package.ecosystem, package.name, package.version, package.path)] = package
    for lock in _dependency_files(root, lambda name: name == "Pipfile.lock"):
        try:
            document = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for section, scope in (("default", "runtime"), ("develop", "development")):
            records = document.get(section, {})
            if not isinstance(records, dict):
                continue
            for name, record in records.items():
                version = record.get("version") if isinstance(record, dict) else None
                match = re.fullmatch(r"={2,3}([^\s;*]+)", version or "")
                if match:
                    package = Package(str(name).lower(), match.group(1), "PyPI", relative_path(lock, root), True, "pipenv", scope)
                    packages[(package.ecosystem, package.name, package.version, package.path)] = package
                else:
                    unresolved.append(f"{relative_path(lock, root)}:{name}")
    requirement = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*(===|==|~=|!=|<=|>=|<|>)?\s*([^\s;#]+)?")
    for lock in _dependency_files(root, lambda name: name.startswith("requirements") and name.endswith(".txt")):
        try:
            lines = lock.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            match = requirement.match(line)
            if not match:
                continue
            name, operator, version = match.groups()
            if operator in {"==", "==="} and version and "*" not in version:
                package = Package(name.lower(), version, "PyPI", relative_path(lock, root), True, "pip")
                packages[(package.ecosystem, package.name.lower(), package.version, package.path)] = package
            else:
                unresolved.append(f"{relative_path(lock, root)}:{name.lower()}")
    return list(packages.values()), unresolved


def discover_packages(root: Path) -> list[Package]:
    return _discover_packages(root)[0]


def discover_dependency_state(root: Path) -> tuple[list[Package], list[str]]:
    """Discover resolved packages and unresolved manifest entries in one tree walk."""
    return _discover_packages(root)


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


def _cvss3_score(vector: str) -> float | None:
    """Calculate a CVSS v3.x Base score using the FIRST v3.1 equations."""
    try:
        parts = vector.split("/")
        if parts[0] not in {"CVSS:3.0", "CVSS:3.1"}:
            return None
        metrics = dict(part.split(":", 1) for part in parts[1:])
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[metrics["AV"]]
        ac = {"L": .77, "H": .44}[metrics["AC"]]
        scope = metrics["S"]
        pr = ({"N": .85, "L": .62, "H": .27} if scope == "U" else {"N": .85, "L": .68, "H": .5})[metrics["PR"]]
        ui = {"N": .85, "R": .62}[metrics["UI"]]
        impacts = {"H": .56, "L": .22, "N": 0}
        iss = 1 - math.prod(1 - impacts[metrics[name]] for name in ("C", "I", "A"))
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        raw = min(impact + exploitability, 10) if scope == "U" else min(1.08 * (impact + exploitability), 10)
        return math.ceil((raw - 1e-10) * 10) / 10
    except (KeyError, ValueError):
        return None


def _cvss_scores(record: dict, package: Package | None = None) -> list[tuple[float, str]]:
    entries = list(record.get("severity", [])) if isinstance(record.get("severity"), list) else []
    for affected in record.get("affected", []):
        identity = affected.get("package", {}) if isinstance(affected, dict) else {}
        if package and identity.get("name", "").lower() != package.name.lower():
            continue
        severity = affected.get("severity", []) if isinstance(affected, dict) else []
        if isinstance(severity, list):
            entries.extend(severity)
    scores = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("score"), str):
            continue
        vector = entry["score"]
        score = None
        if entry.get("type") == "CVSS_V3":
            score = _cvss3_score(vector)
        elif entry.get("type") == "CVSS_V4":
            try:
                score = float(CVSS4(vector).scores()[0])
            except (KeyError, TypeError, ValueError):
                score = None
        if score is not None:
            scores.append((score, vector))
    return scores


def _textual_severity(record: dict, package: Package | None = None) -> Severity | None:
    candidates = [record.get("database_specific", {}).get("severity")]
    for affected in record.get("affected", []):
        identity = affected.get("package", {}) if isinstance(affected, dict) else {}
        if package and identity.get("name", "").lower() != package.name.lower():
            continue
        candidates.append(affected.get("ecosystem_specific", {}).get("severity"))
        candidates.append(affected.get("database_specific", {}).get("severity"))
    values = " ".join(str(item).upper() for item in candidates if item)
    for name in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
        if name in values:
            return Severity.MEDIUM if name == "MODERATE" else Severity[name]
    return None


def _severity(record: dict, package: Package | None = None) -> Severity:
    scores = _cvss_scores(record, package)
    if scores:
        score = max(value for value, _ in scores)
        if score == 0:
            return Severity.INFO
        if score <= 3.9:
            return Severity.LOW
        if score <= 6.9:
            return Severity.MEDIUM
        if score <= 8.9:
            return Severity.HIGH
        return Severity.CRITICAL
    return _textual_severity(record, package) or Severity.UNKNOWN


def _record_aliases(record: dict) -> list[str]:
    aliases = record.get("aliases", [])
    return [alias for alias in aliases if isinstance(alias, str)] if isinstance(aliases, list) else []


def _advisory_groups(advisory_ids: set[str], records: dict[str, dict]) -> list[list[str]]:
    """Return connected components across record IDs and their transitive aliases."""
    groups: list[tuple[set[str], set[str]]] = []
    for advisory_id in sorted(advisory_ids):
        record = records.get(advisory_id, {})
        tokens = {advisory_id, *_record_aliases(record)}
        overlapping = [index for index, (_, known) in enumerate(groups) if known & tokens]
        members = {advisory_id}
        for index in reversed(overlapping):
            prior_members, prior_tokens = groups.pop(index)
            members.update(prior_members)
            tokens.update(prior_tokens)
        groups.append((members, tokens))
    return sorted((sorted(members) for members, _ in groups), key=lambda members: members[0])


def _group_assessment(advisory_ids: list[str], records: dict[str, dict], package: Package) -> tuple[str, Severity, float | None, str | None]:
    scored = []
    textual = []
    for advisory_id in advisory_ids:
        record = records.get(advisory_id, {})
        scores = _cvss_scores(record, package)
        if scores:
            score, vector = max(scores)
            scored.append((score, vector, advisory_id))
        severity = _textual_severity(record, package)
        if severity is not None:
            textual.append((severity, advisory_id))
    if scored:
        score, vector, primary = max(scored, key=lambda item: (item[0], item[2]))
        return primary, _severity(records[primary], package), score, vector
    if textual:
        severity, primary = max(textual, key=lambda item: (int(item[0]), item[1]))
        return primary, severity, None, None
    primary = min(advisory_ids)
    return primary, Severity.UNKNOWN, None, None


def _legacy_fingerprints(advisory_ids: list[str], primary: str, package: Package) -> list[str]:
    evidence = f"{package.name}@{package.version}"
    return [
        hashlib.sha256(f"SCA-{advisory_id}\0{package.path}\01\0{evidence}".encode()).hexdigest()[:20]
        for advisory_id in advisory_ids if advisory_id != primary
    ]


def _group_fixed_version(advisory_ids: list[str], records: dict[str, dict], package: Package) -> tuple[str | None, list[str]]:
    candidates = sorted({
        fixed for advisory_id in advisory_ids
        if (fixed := _fixed_version(records.get(advisory_id, {}), package)) is not None
    }, key=lambda value: _version_key(value, package.ecosystem))
    compatible = [candidate for candidate in candidates if _same_major(package.version, candidate)]
    pool = compatible or candidates
    return (max(pool, key=lambda value: _version_key(value, package.ecosystem)) if pool else None), candidates


def _is_stable_version(value: str, ecosystem: str) -> bool:
    normalized = value.strip().lower()
    if ecosystem.lower() == "go":
        normalized = normalized.removeprefix("v")
    return not bool(re.search(r"(?:[-._+]|\d)(?:a(?:lpha)?|b(?:eta)?|rc|pre(?:view)?|dev|snapshot)\d*", normalized))


def _version_key(value: str, ecosystem: str) -> tuple:
    """Order common ecosystem versions numerically while keeping prereleases below releases."""
    normalized = value.strip().lower()
    if ecosystem.lower() == "go":
        normalized = normalized.removeprefix("v")
    release_text = re.split(r"[-+]|(?<=\d)(?:a(?:lpha)?|b(?:eta)?|rc|pre(?:view)?|dev)", normalized, maxsplit=1)[0]
    release = tuple(int(part) for part in re.findall(r"\d+", release_text)[:8])
    suffix = normalized[len(re.match(r"[vV]?[0-9.]*", normalized).group(0)):] if re.match(r"[vV]?[0-9.]*", normalized) else normalized
    stage = 4
    for marker, rank in (("dev", 0), ("alpha", 1), ("a", 1), ("beta", 2), ("b", 2), ("pre", 3), ("rc", 3), ("snapshot", 3)):
        if marker in suffix:
            stage = rank
            break
    suffix_number = int(re.search(r"\d+", suffix).group(0)) if re.search(r"\d+", suffix) else 0
    return release, stage, suffix_number, normalized


def _fixed_version(record: dict, package: Package) -> str | None:
    candidates = []
    for affected in record.get("affected", []):
        identity = affected.get("package", {})
        if identity.get("name", "").lower() != package.name.lower():
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                if event.get("fixed"):
                    candidates.append(event["fixed"])
    if not candidates:
        return None
    current_major = re.match(r"\D*(\d+)", package.version)
    compatible = [candidate for candidate in candidates if current_major and re.match(r"\D*(\d+)", candidate) and re.match(r"\D*(\d+)", candidate).group(1) == current_major.group(1)]
    pool = compatible or candidates
    stable = [candidate for candidate in pool if _is_stable_version(candidate, package.ecosystem)]
    return min(stable or pool, key=lambda value: _version_key(value, package.ecosystem))


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


def dependency_context(root: Path, package: Package, graph_cache: dict | None = None) -> tuple[list[str], list[list[str]], dict[str, str]]:
    lock = root / package.path
    cache = graph_cache if graph_cache is not None else {}
    cache_key = str(lock.resolve())
    prepared = cache.get(cache_key)
    if prepared is None:
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return [], [], {}
        packages = data.get("packages", {})
        if not isinstance(packages, dict):
            return [], [], {}
        root_package = packages.get("", {})
        runtime_names = set(root_package.get("dependencies", {})) | set(root_package.get("optionalDependencies", {}))
        development_names = set(root_package.get("devDependencies", {}))
        graph: dict[str, list[str]] = {}
        for key, value in packages.items():
            if not isinstance(value, dict):
                continue
            dependencies = set(value.get("dependencies", {})) | set(value.get("optionalDependencies", {}))
            graph[key] = [resolved for name in dependencies if (resolved := _resolve_lock_dependency(packages, key, name))]
        traversals = []
        for name in sorted(runtime_names | development_names):
            start = _resolve_lock_dependency(packages, "", name)
            if not start:
                continue
            paths = {start: [start]}
            pending = [start]
            for key in pending:
                for child in graph.get(key, []):
                    if child not in paths:
                        paths[child] = paths[key] + [child]
                        pending.append(child)
            traversals.append((name, "runtime" if name in runtime_names else "development", paths))
        prepared = packages, traversals
        cache[cache_key] = prepared
    packages, traversals = prepared

    def label(key: str) -> str:
        value = packages.get(key, {})
        name = key.rsplit("node_modules/", 1)[-1]
        version = value.get("version")
        return f"{name}@{version}" if version else name

    parents = []
    paths = []
    scopes = {}
    targets = {
        key for key, value in packages.items() if isinstance(value, dict)
        and key.rsplit("node_modules/", 1)[-1].lower() == package.name.lower()
        and value.get("version") == package.version
    }
    for name, scope, reachable in traversals:
        candidates = [reachable[target] for target in targets if target in reachable]
        if candidates:
            path = min(candidates, key=len)
            parents.append(name)
            paths.append([label(item) for item in path])
            scopes[name] = scope
    return parents, paths[:10], scopes


def direct_parent_packages(root: Path, package: Package) -> list[str]:
    return dependency_context(root, package)[0]


def scan_dependencies(root: Path, timeout: float = 10, cache_dir: Path | bool | None = None, discovery: tuple[list[Package], list[str]] | None = None) -> tuple[list[Finding], str | None]:
    packages, unresolved = discovery if discovery is not None else _discover_packages(root)
    coverage_warning = None
    if unresolved:
        locations = ", ".join(unresolved[:5])
        remainder = f" and {len(unresolved) - 5} more" if len(unresolved) > 5 else ""
        coverage_warning = f"{len(unresolved)} unpinned Python requirement(s) were not evaluated: {locations}{remainder}"
    if not packages:
        return [], coverage_warning
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
        unavailable = f"OSV dependency scan unavailable: {error}"
        return [], f"{coverage_warning}; {unavailable}" if coverage_warning else unavailable
    findings = []
    graph_cache: dict = {}
    for package, result in zip(packages, normalized_results):
        active_ids = {
            summary["id"] for summary in result.get("vulns", [])
            if isinstance(summary, dict) and isinstance(summary.get("id"), str)
            and not records.get(summary["id"], {}).get("withdrawn")
        }
        for advisory_ids in _advisory_groups(active_ids, records):
            primary, severity, cvss_score, cvss_vector = _group_assessment(advisory_ids, records, package)
            record = records.get(primary, {})
            fixed, fixed_candidates = _group_fixed_version(advisory_ids, records, package)
            same_major = _same_major(package.version, fixed)
            parent_packages, dependency_paths, parent_scopes = dependency_context(root, package, graph_cache) if package.manager == "npm" and not package.direct else ([], [], {})
            root_pnpm = package.manager == "pnpm" and package.path == "pnpm-lock.yaml"
            fix_eligible = bool(package.direct and same_major and (package.manager in {"npm", "pip"} or root_pnpm))
            if package.manager not in {"npm", "pip", "pnpm"}:
                fix_block_reason = f"Vulcanary scans {package.manager} locks read-only; automatic upgrades are not enabled yet"
            elif package.manager == "pnpm" and not root_pnpm:
                fix_block_reason = "Nested pnpm workspace upgrades require an explicit workspace target"
            elif not fixed:
                fix_block_reason = "The advisory does not identify a patched release yet"
            elif not same_major:
                fix_block_reason = f"The fix requires a major upgrade to {fixed}"
            elif not package.direct:
                candidates = ", ".join(parent_packages) if parent_packages else "the introducing direct dependency"
                fix_block_reason = f"Upgrade {candidates}; unscoped transitive overrides can break other dependency paths"
            else:
                fix_block_reason = None
            aliases = sorted({
                alias for advisory_id in advisory_ids
                for alias in [advisory_id, *_record_aliases(records.get(advisory_id, {}))]
            })
            remediation = f"Upgrade {package.name} to {fixed} or later." if fixed else f"Review {primary} and upgrade {package.name} to a non-affected release."
            findings.append(Finding(
                f"SCA-{primary}", record.get("summary") or f"Vulnerable dependency: {package.name}",
                f"{package.name} {package.version} is affected by {primary} and its linked advisory records.", severity, "dependency",
                package.path, 1, f"{package.name}@{package.version}", remediation, "osv", {
                    "package": package.name,
                    "current_version": package.version,
                    "fixed_version": fixed,
                    "fixed_version_candidates": fixed_candidates,
                    "ecosystem": package.ecosystem,
                    "manager": package.manager,
                    "scope": package.scope,
                    "direct": package.direct,
                    "fix_eligible": fix_eligible,
                    "fix_block_reason": fix_block_reason,
                    "parent_packages": parent_packages,
                    "dependency_paths": dependency_paths,
                    "parent_scopes": parent_scopes,
                    "fix_strategy": "pip" if package.manager == "pip" else "dependency" if package.direct else "override",
                    "dependency_file": package.path,
                    "advisory": primary,
                    "advisories": advisory_ids,
                    "aliases": aliases,
                    "legacy_fingerprints": _legacy_fingerprints(advisory_ids, primary, package),
                    "severity_source": "cvss" if cvss_score is not None else "textual" if severity != Severity.UNKNOWN else "unknown",
                    "cvss": {"score": cvss_score, "vector": cvss_vector} if cvss_score is not None else None,
                },
            ))
    return findings, coverage_warning
