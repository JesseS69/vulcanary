from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from .config import Config
from .dependencies import scan_dependencies
from .fixes import run_verification


def _run(command: list[str], cwd: Path, timeout: int = 180, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(command[0]) or shutil.which(f"{command[0]}.cmd") or command[0]
    return subprocess.run([executable, *command[1:]], cwd=cwd, text=True, capture_output=True, timeout=timeout, shell=False, env=environment)


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value)[:3])


def _declared_direct_packages(root: Path) -> dict[str, str]:
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    return {**package.get("dependencies", {}), **package.get("devDependencies", {})}


def _compatibility_line(specification: str) -> tuple[int, ...] | None:
    parts = [int(part) for part in re.findall(r"\d+", specification)[:2]]
    if not parts:
        return None
    return tuple(parts[:2]) if parts[0] == 0 and len(parts) > 1 else (parts[0],)


def latest_same_major(root: Path, package: str, specification: str) -> str | None:
    compatibility = _compatibility_line(specification)
    if compatibility is None:
        return None
    selector = ".".join(str(part) for part in compatibility)
    completed = _run(["npm", "view", f"{package}@{selector}", "version", "--json"], root, 60)
    if completed.returncode:
        return None
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError):
        return None
    versions = payload if isinstance(payload, list) else [payload]
    compatible = [version for version in versions if isinstance(version, str) and _compatibility_line(version) == compatibility]
    return max(compatible, key=_version_key) if compatible else None


def parent_candidates(findings: list[dict], repository: str) -> list[dict]:
    root = Path(repository).resolve()
    declared = _declared_direct_packages(root)
    grouped: dict[str, dict] = {}
    for finding in findings:
        if finding.get("repository_path") != str(root):
            continue
        metadata = finding.get("metadata", {})
        for parent in metadata.get("parent_packages", []):
            if parent not in declared:
                continue
            item = grouped.setdefault(parent, {"package": parent, "specification": declared[parent], "advisories": set(), "vulnerable_packages": set()})
            item["advisories"].add(metadata.get("advisory"))
            item["vulnerable_packages"].add(metadata.get("package"))
    return [dict(item, advisories=sorted(item["advisories"] - {None}), vulnerable_packages=sorted(item["vulnerable_packages"] - {None})) for item in grouped.values()]


def evaluate_parent_upgrades(
    findings: list[dict],
    repository: str,
    dependency_scanner: Callable[[Path], tuple[list, str | None]] = scan_dependencies,
    packages: set[str] | None = None,
) -> dict:
    root = Path(repository).resolve()
    git_root_result = _run(["git", "rev-parse", "--show-toplevel"], root, 30)
    if git_root_result.returncode:
        raise ValueError("Parent evaluation requires a Git repository")
    git_root = Path(git_root_result.stdout.strip()).resolve()
    relative_root = root.relative_to(git_root)
    if _run(["git", "status", "--porcelain"], git_root, 30).stdout.strip():
        raise ValueError("Repository has uncommitted changes; parent evaluation requires a clean checkpoint")
    config = Config.load(root)
    results = []
    candidates = parent_candidates(findings, str(root))
    if packages:
        candidates = [candidate for candidate in candidates if candidate["package"] in packages]
    for candidate in candidates:
        target = latest_same_major(root, candidate["package"], candidate["specification"])
        if not target:
            results.append(dict(candidate, status="no_candidate", candidate_version=None))
            continue
        with tempfile.TemporaryDirectory(prefix="vulcanary-parent-") as directory:
            worktree = Path(directory)
            added = _run(["git", "worktree", "add", "--detach", str(worktree), "HEAD"], git_root, 60)
            if added.returncode:
                results.append(dict(candidate, status="worktree_failed", candidate_version=target))
                continue
            project = worktree / relative_root
            try:
                installed = _run(["npm", "install", f"{candidate['package']}@{target}", "--ignore-scripts", "--no-audit", "--no-fund"], project, 600)
                if installed.returncode:
                    results.append(dict(candidate, status="install_failed", candidate_version=target))
                    continue
                rescanned, warning = dependency_scanner(project)
                remaining_rules = {finding.rule_id for finding in rescanned}
                remaining = sorted(advisory for advisory in candidate["advisories"] if f"SCA-{advisory}" in remaining_rules)
                resolved = sorted(set(candidate["advisories"]) - set(remaining))
                if remaining:
                    status = "partial_improvement" if resolved else "still_vulnerable"
                    results.append(dict(candidate, status=status, candidate_version=target, remaining=remaining, resolved=resolved))
                    continue
                verification = run_verification(str(project), config.verify_commands, config.verify_timeout_seconds)
                status = "safe_candidate" if verification["passed"] and not verification.get("skipped") else "verification_skipped" if verification.get("skipped") else "verification_failed"
                results.append(dict(candidate, status=status, candidate_version=target, verification=verification, warning=warning))
            finally:
                _run(["git", "worktree", "remove", "--force", str(worktree)], git_root, 60)
    return {"repository": str(root), "results": results}


def evaluate_expo_platform(findings: list[dict], repository: str, test_migration: bool = False) -> dict:
    root = Path(repository).resolve()
    declared = _declared_direct_packages(root)
    if "expo" not in declared:
        raise ValueError("Expo is not a direct dependency of this repository")
    git_root_result = _run(["git", "rev-parse", "--show-toplevel"], root, 30)
    if git_root_result.returncode:
        raise ValueError("Platform evaluation requires a Git repository")
    git_root = Path(git_root_result.stdout.strip()).resolve()
    relative_root = root.relative_to(git_root)
    if _run(["git", "status", "--porcelain"], git_root, 30).stdout.strip():
        raise ValueError("Repository has uncommitted changes; platform evaluation requires a clean checkpoint")
    current_line = _compatibility_line(declared["expo"])
    next_line = str((current_line or (0,))[0] + 1)
    migration_candidate = latest_same_major(root, "expo", next_line)
    current = migration_candidate if test_migration else latest_same_major(root, "expo", declared["expo"])
    is_migration = test_migration
    if not current:
        return {"repository": str(root), "status": "no_candidate", "migration_candidate": migration_candidate, "is_migration": is_migration}
    target_advisories = sorted({
        finding.get("metadata", {}).get("advisory")
        for finding in findings
        if finding.get("repository_path") == str(root) and "expo" in finding.get("metadata", {}).get("parent_packages", [])
    } - {None})
    with tempfile.TemporaryDirectory(prefix="vulcanary-platform-") as directory:
        worktree = Path(directory)
        added = _run(["git", "worktree", "add", "--detach", str(worktree), "HEAD"], git_root, 60)
        if added.returncode:
            return {"repository": str(root), "status": "worktree_failed", "candidate_version": current, "migration_candidate": migration_candidate, "is_migration": is_migration}
        project = worktree / relative_root
        safe_environment = dict(os.environ, npm_config_ignore_scripts="true", npm_config_audit="false", npm_config_fund="false")
        try:
            installed = _run(["npm", "install", f"expo@{current}", "--ignore-scripts", "--no-audit", "--no-fund"], project, 600, safe_environment)
            if installed.returncode:
                return {"repository": str(root), "status": "install_failed", "candidate_version": current, "migration_candidate": migration_candidate, "is_migration": is_migration}
            expo_binary = project / "node_modules" / ".bin" / ("expo.cmd" if os.name == "nt" else "expo")
            aligned = _run([str(expo_binary), "install", "--fix", "--npm", "--", "--ignore-scripts", "--no-audit", "--no-fund"], project, 900, safe_environment)
            if aligned.returncode:
                return {"repository": str(root), "status": "alignment_failed", "candidate_version": current, "migration_candidate": migration_candidate, "is_migration": is_migration}
            checked = _run([str(expo_binary), "install", "--check", "--json"], project, 180, safe_environment)
            rescanned, warning = scan_dependencies(project)
            remaining_rules = {finding.rule_id for finding in rescanned}
            remaining = sorted(advisory for advisory in target_advisories if f"SCA-{advisory}" in remaining_rules)
            resolved = sorted(set(target_advisories) - set(remaining))
            config = Config.load(root)
            verification = run_verification(str(project), config.verify_commands, config.verify_timeout_seconds)
            status = "safe_candidate" if not remaining and verification["passed"] and not verification.get("skipped") else "verification_skipped" if not remaining else "partial_improvement" if resolved else "still_vulnerable"
            changed = _run(["git", "diff", "--name-only"], worktree, 30).stdout.splitlines()
            updated = _declared_direct_packages(project)
            package_changes = [
                {"package": name, "from": declared.get(name), "to": updated.get(name)}
                for name in sorted(set(declared) | set(updated)) if declared.get(name) != updated.get(name)
            ]
            return {
                "repository": str(root), "status": status, "candidate_version": current,
                "migration_candidate": migration_candidate, "is_migration": is_migration, "remaining": remaining, "resolved": resolved,
                "advisories": target_advisories, "expo_check_passed": checked.returncode == 0,
                "verification": verification, "changed_files": sorted(changed), "package_changes": package_changes, "warning": warning,
            }
        finally:
            _run(["git", "worktree", "remove", "--force", str(worktree)], git_root, 60)
