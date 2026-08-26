from __future__ import annotations

import json
import subprocess
import re
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
            item["reason"] = "Requires a transitive, major-version, or manual source change"
            blocked.append(item)
    return {"changes": list(changes_by_package.values()), "blocked": blocked, "selected": len(selected)}


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(root), *args], text=True, capture_output=True, timeout=30)


def apply_changes(plan: dict) -> dict:
    if not plan.get("changes"):
        raise ValueError("No safe automatic fixes were selected")
    roots = {item["repository_path"] for item in plan["changes"]}
    if len(roots) != 1:
        raise ValueError("Apply fixes to one repository at a time")
    root = Path(roots.pop()).resolve()
    if _git(root, "status", "--porcelain").stdout.strip():
        raise ValueError("Repository has uncommitted changes; commit or stash them before applying fixes")
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
    command = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    try:
        completed = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=180)
    except (subprocess.TimeoutExpired, OSError) as error:
        _git(root, "restore", "package.json", "package-lock.json")
        _git(root, "switch", "-")
        _git(root, "branch", "-D", branch)
        raise ValueError(f"npm could not refresh the lockfile: {error}") from error
    if completed.returncode:
        _git(root, "restore", "package.json", "package-lock.json")
        _git(root, "switch", "-")
        _git(root, "branch", "-D", branch)
        raise ValueError(completed.stderr.strip() or "npm could not refresh the lockfile")
    return {"repository": str(root), "branch": branch, "files": ["package.json", "package-lock.json"]}


def commit_changes(repository: str, branch: str) -> dict:
    root = Path(repository).resolve()
    current = _git(root, "branch", "--show-current").stdout.strip()
    if current != branch or not branch.startswith("vulcanary/fixes-"):
        raise ValueError("The repository is not on the expected Vulcanary fix branch")
    _git(root, "add", "--", "package.json", "package-lock.json")
    committed = _git(root, "commit", "-m", "fix: apply verified Vulcanary dependency upgrades")
    if committed.returncode:
        raise ValueError(committed.stderr.strip() or "Could not commit fixes")
    return {"repository": str(root), "branch": branch, "commit": _git(root, "rev-parse", "HEAD").stdout.strip()}
