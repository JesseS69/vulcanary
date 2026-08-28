from __future__ import annotations

import difflib
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


_STATIC_INNER_HTML = re.compile(
    r"^(?P<indent>\s*)(?P<element>[A-Za-z_$][\w$]*)\.innerHTML = `"
    r"<span aria-hidden=\"true\" style=\"(?P<style>[^\"]*)\">(?P<icon>[^<]*)</span>"
    r"\$\{(?P<condition>[A-Za-z_$][\w$]*) \? '<span>(?P<label>[^<]*)</span>' : ''\}`;$"
)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    roots = [candidate for candidate in (root, *root.parents) if (candidate / ".git").exists()] or [root]
    safe = [argument for candidate in roots for argument in ("-c", f"safe.directory={candidate.as_posix()}")]
    return subprocess.run(["git", *safe, "-C", str(root), *args], text=True, capture_output=True, timeout=30)


def preview_source_fix(finding: dict) -> dict:
    if finding.get("rule_id") != "CODE-JS-INNERHTML":
        raise ValueError("No verified source-fix recipe exists for this rule")
    root = Path(finding["repository_path"]).resolve()
    relative = Path(finding["path"])
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError("Finding path escapes the repository") from error
    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    line_number = int(finding["line"])
    if line_number < 1 or line_number > len(lines):
        raise ValueError("Finding line is outside the source file")
    original = lines[line_number - 1].rstrip("\r\n")
    match = _STATIC_INNER_HTML.fullmatch(original)
    if not match:
        raise ValueError("This innerHTML shape needs contextual review; no deterministic recipe was applied")
    values = match.groupdict()
    indent = values["indent"]
    element = values["element"]
    replacement_lines = [
        f"{indent}{element}.replaceChildren();",
        f"{indent}const vulcanaryIcon = document.createElement('span');",
        f"{indent}vulcanaryIcon.setAttribute('aria-hidden', 'true');",
        f"{indent}vulcanaryIcon.style.cssText = {values['style']!r};",
        f"{indent}vulcanaryIcon.textContent = {values['icon']!r};",
        f"{indent}{element}.append(vulcanaryIcon);",
        f"{indent}if ({values['condition']}) {{",
        f"{indent}  const vulcanaryLabel = document.createElement('span');",
        f"{indent}  vulcanaryLabel.textContent = {values['label']!r};",
        f"{indent}  {element}.append(vulcanaryLabel);",
        f"{indent}}}",
    ]
    newline = "\r\n" if lines[line_number - 1].endswith("\r\n") else "\n"
    replacement_parts = [line + newline for line in replacement_lines]
    replacement = "".join(replacement_parts)
    revised = [*lines[:line_number - 1], *replacement_parts, *lines[line_number:]]
    diff = "".join(difflib.unified_diff(lines, revised, fromfile=f"a/{relative.as_posix()}", tofile=f"b/{relative.as_posix()}"))
    changes = [{"file": relative.as_posix(), "original": original, "replacement": replacement.rstrip("\r\n")}]
    regression = root / "scripts" / "beta-regression-checks.js"
    if regression.exists():
        regression_text = regression.read_text(encoding="utf-8")
        marker = f'requireText(\'{relative.as_posix()}\', "{values["condition"]} ? \'<span>{values["label"]}</span>\' : \'\'");'
        if marker in regression_text:
            marker_replacement = (
                f"requireText('{relative.as_posix()}', \"{element}.replaceChildren()\");\n"
                f"requireText('{relative.as_posix()}', \"vulcanaryLabel.textContent = '{values['label']}'\");"
            )
            regression_lines = regression_text.splitlines(keepends=True)
            revised_regression = regression_text.replace(marker, marker_replacement, 1).splitlines(keepends=True)
            diff += "".join(difflib.unified_diff(
                regression_lines, revised_regression,
                fromfile="a/scripts/beta-regression-checks.js", tofile="b/scripts/beta-regression-checks.js",
            ))
            changes.append({"file": "scripts/beta-regression-checks.js", "original": marker, "replacement": marker_replacement})
    funnel = root / "tests" / "security" / "onboardingFunnel.test.mjs"
    if funnel.exists():
        funnel_text = funnel.read_text(encoding="utf-8")
        funnel_marker = f"  assert.match(socialFeed, /{values['condition']} \\? '<span>{values['label']}<\\/span>' : ''/);"
        if funnel_marker in funnel_text:
            funnel_replacement = (
                f"  assert.match(socialFeed, /{element}\\.replaceChildren\\(\\)/);\n"
                f"  assert.match(socialFeed, /vulcanaryLabel\\.textContent = '{values['label']}'/);"
            )
            funnel_lines = funnel_text.splitlines(keepends=True)
            revised_funnel = funnel_text.replace(funnel_marker, funnel_replacement, 1).splitlines(keepends=True)
            diff += "".join(difflib.unified_diff(
                funnel_lines, revised_funnel,
                fromfile="a/tests/security/onboardingFunnel.test.mjs", tofile="b/tests/security/onboardingFunnel.test.mjs",
            ))
            changes.append({"file": "tests/security/onboardingFunnel.test.mjs", "original": funnel_marker, "replacement": funnel_replacement})
    return {
        "fingerprint": finding["fingerprint"], "repository": str(root), "file": relative.as_posix(),
        "line": line_number, "rule_id": finding["rule_id"], "recipe": "static-innerhtml-to-dom",
        "diff": diff, "changes": changes, "files": [change["file"] for change in changes],
    }


def apply_source_fix(proposal: dict) -> dict:
    root = Path(proposal["repository"]).resolve()
    if _git(root, "status", "--porcelain").stdout.strip():
        raise ValueError("Repository has uncommitted changes; source fixes require a clean checkpoint")
    original_branch = _git(root, "branch", "--show-current").stdout.strip()
    if not original_branch:
        raise ValueError("Repository must be on a named branch")
    branch = f"vulcanary/source-fix-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    switched = _git(root, "switch", "-c", branch)
    if switched.returncode:
        raise ValueError(switched.stderr.strip() or "Could not create the source-fix branch")
    for change in proposal["changes"]:
        target = (root / change["file"]).resolve()
        text = target.read_text(encoding="utf-8")
        original = change["original"]
        if text.count(original) != 1:
            _git(root, "restore", "--source=HEAD", "--staged", "--worktree", "--", ".")
            _git(root, "switch", original_branch)
            _git(root, "branch", "-D", branch)
            raise ValueError("Source changed after preview; regenerate the fix before applying")
        target.write_text(text.replace(original, change["replacement"], 1), encoding="utf-8")
    return {
        "repository": str(root), "branch": branch, "original_branch": original_branch,
        "files": proposal["files"], "fingerprint": proposal["fingerprint"], "strategy": "source",
    }
