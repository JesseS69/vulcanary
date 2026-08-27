from __future__ import annotations

import json
import subprocess
import re
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


def preview(findings: list[dict], fingerprints: list[str]) -> dict:
    selected = [item for item in findings if item.get("fingerprint") in set(fingerprints)]
    changes_by_package: dict[tuple[str, str], dict] = {}
    blocked = []
    for finding in selected:
        meta = finding.get("metadata", {})
        item = {
            "fingerprint": finding["fingerprint"], "title": finding["title"],
            "repository": finding["repository"], "repository_path": finding["repository_path"],
            "package": meta.get("package"), "from": meta.get("current_version"),
            "to": meta.get("fixed_version"), "advisory": meta.get("advisory"),
            "files": ["package.json", "package-lock.json"],
            "strategy": meta.get("fix_strategy"),
        }
        verified = meta.get("verified_fix")
        if verified and verified.get("strategy") == "platform":
            item.update(
                package="expo", to=verified.get("candidate_version"), strategy="platform",
                is_migration=bool(verified.get("is_migration")), files=["package.json", "package-lock.json"],
            )
        if meta.get("fix_eligible"):
            key = (item["repository_path"], item["package"])
            existing = changes_by_package.get(key)
            item["advisories"] = [item["advisory"]]
            if existing:
                existing["advisories"].append(item["advisory"])
                version_key = lambda value: tuple(int(part) for part in re.findall(r"\d+", value or "0"))
                if version_key(item["to"]) > version_key(existing["to"]):
                    existing["to"] = item["to"]
            else:
                changes_by_package[key] = item
        else:
            item["reason"] = meta.get("fix_block_reason") or "Requires a transitive, major-version, or manual source change"
            blocked.append(item)
    return {"changes": list(changes_by_package.values()), "blocked": blocked, "selected": len(selected)}


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    git_roots = [candidate for candidate in (root, *root.parents) if (candidate / ".git").exists()] or [root]
    safe_directories = [argument for candidate in git_roots for argument in ("-c", f"safe.directory={candidate.as_posix()}")]
    return subprocess.run(["git", *safe_directories, "-C", str(root), *args], text=True, capture_output=True, timeout=30)


def _resolve_executable(command: list[str]) -> list[str]:
    executable = shutil.which(command[0]) or shutil.which(f"{command[0]}.cmd") or command[0]
    return [executable, *command[1:]]


def rollback_changes(repository: str, branch: str, original_branch: str) -> dict:
    root = Path(repository).resolve()
    current = _git(root, "branch", "--show-current").stdout.strip()
    allowed = ("vulcanary/fixes-", "vulcanary/fix-expo-", "vulcanary/migrate-expo-")
    if current != branch or not branch.startswith(allowed):
        raise ValueError("Rollback refused: repository is not on the expected Vulcanary fix branch")
    restored = _git(root, "restore", "--source=HEAD", "--staged", "--worktree", "--", ".")
    if restored.returncode:
        raise ValueError(restored.stderr.strip() or "Rollback could not restore npm files")
    switched = _git(root, "switch", original_branch)
    if switched.returncode:
        raise ValueError(switched.stderr.strip() or "Rollback could not restore the original branch")
    removed = _git(root, "branch", "-D", branch)
    if removed.returncode:
        raise ValueError(removed.stderr.strip() or "Rollback could not remove the failed fix branch")
    return {
        "completed": True,
        "original_branch": original_branch,
        "removed_branch": branch,
        "restored_files": ["tracked Vulcanary changes"],
    }


def run_verification(repository: str, commands: list[list[str]], timeout_seconds: int = 300) -> dict:
    root = Path(repository).resolve()
    results = []
    for index, command in enumerate(commands, start=1):
        label = f"check {index} ({Path(command[0]).name})"
        try:
            completed = subprocess.run(
                _resolve_executable(command), cwd=root, text=True, capture_output=True, timeout=timeout_seconds, shell=False,
            )
        except subprocess.TimeoutExpired:
            return {"passed": False, "failed_command": label, "reason": "timed out", "results": results}
        except OSError:
            return {"passed": False, "failed_command": label, "reason": "could not start", "results": results}
        diagnostics = []
        for match in re.finditer(r"(?m)^(.+?)\((\d+),(\d+)\):\s+error\s+(TS\d+):", f"{completed.stdout}\n{completed.stderr}"):
            path = Path(match.group(1).strip())
            try:
                rendered_path = path.resolve().relative_to(root).as_posix() if path.is_absolute() else path.as_posix()
            except ValueError:
                rendered_path = path.name
            diagnostics.append({"path": rendered_path, "line": int(match.group(2)), "column": int(match.group(3)), "code": match.group(4)})
        results.append({"command": label, "returncode": completed.returncode, "diagnostics": diagnostics[:100]})
        if completed.returncode:
            return {"passed": False, "failed_command": label, "reason": "returned a non-zero status", "results": results, "diagnostics": diagnostics[:100]}
    return {"passed": True, "skipped": not commands, "results": results}


def apply_changes(plan: dict) -> dict:
    if not plan.get("changes"):
        raise ValueError("No safe automatic fixes were selected")
    roots = {item["repository_path"] for item in plan["changes"]}
    if len(roots) != 1:
        raise ValueError("Apply fixes to one repository at a time")
    root = Path(roots.pop()).resolve()
    if _git(root, "status", "--porcelain").stdout.strip():
        raise ValueError("Repository has uncommitted changes; commit or stash them before applying fixes")
    original_branch = _git(root, "branch", "--show-current").stdout.strip()
    if not original_branch:
        raise ValueError("Repository must be on a named branch before applying fixes")
    branch = f"vulcanary/fixes-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    switched = _git(root, "switch", "-c", branch)
    if switched.returncode:
        raise ValueError(switched.stderr.strip() or "Could not create fix branch")
    package_path = root / "package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    for item in plan["changes"]:
        if item.get("strategy") == "override":
            package.setdefault("overrides", {})[item["package"]] = item["to"]
        else:
            for section in ("dependencies", "devDependencies"):
                if item["package"] in package.get(section, {}):
                    old = package[section][item["package"]]
                    prefix = "^" if str(old).startswith("^") else "~" if str(old).startswith("~") else ""
                    package[section][item["package"]] = prefix + item["to"]
    package_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    command = _resolve_executable(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"])
    try:
        completed = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=180)
    except (subprocess.TimeoutExpired, OSError) as error:
        rollback_changes(str(root), branch, original_branch)
        raise ValueError(f"npm could not refresh the lockfile; all changes were rolled back ({type(error).__name__})") from error
    if completed.returncode:
        rollback_changes(str(root), branch, original_branch)
        raise ValueError("npm could not refresh the lockfile; all changes were rolled back")
    return {"repository": str(root), "branch": branch, "original_branch": original_branch, "files": ["package.json", "package-lock.json"]}


def commit_changes(repository: str, branch: str) -> dict:
    root = Path(repository).resolve()
    current = _git(root, "branch", "--show-current").stdout.strip()
    allowed = ("vulcanary/fixes-", "vulcanary/fix-expo-", "vulcanary/migrate-expo-")
    if current != branch or not branch.startswith(allowed):
        raise ValueError("The repository is not on the expected Vulcanary fix branch")
    _git(root, "add", "-u")
    message = "fix: apply verified Vulcanary remediation" if "expo-" in branch else "fix: apply verified Vulcanary dependency upgrades"
    committed = _git(root, "commit", "-m", message)
    if committed.returncode:
        raise ValueError(committed.stderr.strip() or "Could not commit fixes")
    return {"repository": str(root), "branch": branch, "commit": _git(root, "rev-parse", "HEAD").stdout.strip()}
