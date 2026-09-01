from __future__ import annotations

import ast
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
_PYTHON_LITERAL_EVAL = re.compile(
    r"^(?P<indent>\s*)(?P<prefix>(?:(?:return|yield)\s+|[A-Za-z_]\w*\s*=\s*)?)"
    r"eval\((?P<argument>[^()]+)\)(?P<suffix>\s*(?:#.*)?)$"
)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    roots = [candidate for candidate in (root, *root.parents) if (candidate / ".git").exists()] or [root]
    safe = [argument for candidate in roots for argument in ("-c", f"safe.directory={candidate.as_posix()}")]
    return subprocess.run(["git", *safe, "-C", str(root), *args], text=True, capture_output=True, timeout=30)


def _preview_static_innerhtml(finding: dict) -> dict:
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


def _preview_python_literal_eval(finding: dict) -> dict:
    root = Path(finding["repository_path"]).resolve()
    relative = Path(finding["path"])
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError("Finding path escapes the repository") from error
    text = target.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    line_number = int(finding["line"])
    if line_number < 1 or line_number > len(lines):
        raise ValueError("Finding line is outside the source file")
    original_line = lines[line_number - 1].rstrip("\r\n")
    match = _PYTHON_LITERAL_EVAL.fullmatch(original_line)
    if not match:
        raise ValueError("This eval shape needs contextual review; only a standalone literal-data expression can use the deterministic recipe")
    argument = match.group("argument").strip()
    if not re.fullmatch(r"[A-Za-z_]\w*(?:\[[^\]]+\]|\.\w+)*", argument):
        raise ValueError("This eval argument is not a simple data value; contextual review is required")
    newline = "\r\n" if lines[line_number - 1].endswith("\r\n") else "\n"
    replacement_line = (
        f"{match.group('indent')}{match.group('prefix')}ast.literal_eval({argument}){match.group('suffix')}"
    )
    revised_lines = list(lines)
    revised_lines[line_number - 1] = replacement_line + newline
    if not re.search(r"(?m)^\s*import\s+ast(?:\s|$)", text):
        try:
            module = ast.parse(text)
        except SyntaxError as error:
            raise ValueError("Python source must parse before Vulcanary can draft a fix") from error
        insertion = 1 if lines and lines[0].startswith("#!") else 0
        if insertion < len(lines) and re.match(r"^#.*coding[:=]\s*[-\w.]+", lines[insertion]):
            insertion += 1
        if module.body and isinstance(module.body[0], ast.Expr) and isinstance(module.body[0].value, ast.Constant) and isinstance(module.body[0].value.value, str):
            insertion = max(insertion, int(module.body[0].end_lineno or module.body[0].lineno))
        while insertion < len(lines) and re.match(r"^\s*from\s+__future__\s+import\b", lines[insertion]):
            insertion += 1
        revised_lines.insert(insertion, f"import ast{newline}")
    revised = "".join(revised_lines)
    diff = "".join(difflib.unified_diff(
        text.splitlines(keepends=True), revised.splitlines(keepends=True),
        fromfile=f"a/{relative.as_posix()}", tofile=f"b/{relative.as_posix()}",
    ))
    return {
        "fingerprint": finding["fingerprint"], "repository": str(root), "file": relative.as_posix(),
        "line": line_number, "rule_id": finding["rule_id"], "recipe": "python-eval-to-literal-eval",
        "diff": diff, "changes": [{"file": relative.as_posix(), "original": text, "replacement": revised}],
        "files": [relative.as_posix()],
    }


def _preview_python_shell_false(finding: dict) -> dict:
    root = Path(finding["repository_path"]).resolve()
    relative = Path(finding["path"])
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError("Finding path escapes the repository") from error
    text = target.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    line_number = int(finding["line"])
    if line_number < 1 or line_number > len(lines):
        raise ValueError("Finding line is outside the source file")
    original_line = lines[line_number - 1].rstrip("\r\n")
    try:
        parsed = ast.parse(original_line.strip())
    except SyntaxError as error:
        raise ValueError("This subprocess call needs contextual review; only a complete single-line call can use the deterministic recipe") from error
    calls = [node for node in ast.walk(parsed) if isinstance(node, ast.Call)]
    candidates = []
    for call in calls:
        function = call.func
        is_subprocess = (
            isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name)
            and function.value.id == "subprocess" and function.attr in {"run", "Popen", "call"}
        )
        shell_keywords = [keyword for keyword in call.keywords if keyword.arg == "shell"]
        static_argv = bool(call.args) and isinstance(call.args[0], (ast.List, ast.Tuple)) and all(
            isinstance(item, ast.Constant) and isinstance(item.value, str) for item in call.args[0].elts
        )
        if is_subprocess and len(shell_keywords) == 1 and isinstance(shell_keywords[0].value, ast.Constant) and shell_keywords[0].value.value is True and static_argv:
            candidates.append(call)
    if len(candidates) != 1:
        raise ValueError("This subprocess call needs contextual review; a static string-only argument list and one shell=True flag are required")
    revised_line, replacements = re.subn(r",\s*shell\s*=\s*True\b", "", original_line, count=1)
    if replacements != 1:
        revised_line, replacements = re.subn(r"shell\s*=\s*True\s*,\s*", "", original_line, count=1)
    if replacements != 1:
        raise ValueError("The shell flag could not be removed without changing the command structure")
    newline = "\r\n" if lines[line_number - 1].endswith("\r\n") else "\n"
    revised_lines = list(lines)
    revised_lines[line_number - 1] = revised_line + newline
    revised = "".join(revised_lines)
    diff = "".join(difflib.unified_diff(
        text.splitlines(keepends=True), revised.splitlines(keepends=True),
        fromfile=f"a/{relative.as_posix()}", tofile=f"b/{relative.as_posix()}",
    ))
    return {
        "fingerprint": finding["fingerprint"], "repository": str(root), "file": relative.as_posix(),
        "line": line_number, "rule_id": finding["rule_id"], "recipe": "python-static-argv-without-shell",
        "diff": diff, "changes": [{"file": relative.as_posix(), "original": text, "replacement": revised}],
        "files": [relative.as_posix()],
    }


def _preview_disable_persisted_credentials(finding: dict) -> dict:
    root = Path(finding["repository_path"]).resolve()
    relative = Path(finding["path"])
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError("Finding path escapes the repository") from error
    if ".github/workflows/" not in f"/{relative.as_posix()}":
        raise ValueError("Persisted-credential fixes apply only to GitHub workflow files")
    text = target.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    line_number = int(finding["line"])
    if line_number < 1 or line_number > len(lines):
        raise ValueError("Finding line is outside the workflow")
    original_line = lines[line_number - 1].rstrip("\r\n")
    revised_line, count = re.subn(r"(?i)(persist-credentials\s*:\s*)true(\s*(?:#.*)?)$", r"\1false\2", original_line)
    if count != 1:
        raise ValueError("The workflow changed after scanning; regenerate the fix")
    newline = "\r\n" if lines[line_number - 1].endswith("\r\n") else "\n"
    revised_lines = list(lines)
    revised_lines[line_number - 1] = revised_line + newline
    revised = "".join(revised_lines)
    diff = "".join(difflib.unified_diff(
        text.splitlines(keepends=True), revised.splitlines(keepends=True),
        fromfile=f"a/{relative.as_posix()}", tofile=f"b/{relative.as_posix()}",
    ))
    return {
        "fingerprint": finding["fingerprint"], "repository": str(root), "file": relative.as_posix(),
        "line": line_number, "rule_id": finding["rule_id"], "recipe": "github-checkout-disable-persisted-credentials",
        "diff": diff, "changes": [{"file": relative.as_posix(), "original": text, "replacement": revised}],
        "files": [relative.as_posix()],
    }


def _preview_reduce_write_all(finding: dict) -> dict:
    root = Path(finding["repository_path"]).resolve()
    relative = Path(finding["path"])
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError("Finding path escapes the repository") from error
    if ".github/workflows/" not in f"/{relative.as_posix()}":
        raise ValueError("Workflow permission fixes apply only to GitHub workflow files")
    text = target.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    line_number = int(finding["line"])
    if line_number < 1 or line_number > len(lines):
        raise ValueError("Finding line is outside the workflow")
    original_line = lines[line_number - 1].rstrip("\r\n")
    revised_line, count = re.subn(r"(?i)^(\s*permissions\s*:\s*)write-all(\s*(?:#.*)?)$", r"\1read-all\2", original_line)
    if count != 1:
        raise ValueError("The workflow changed after scanning; regenerate the fix")
    newline = "\r\n" if lines[line_number - 1].endswith("\r\n") else "\n"
    revised_lines = list(lines)
    revised_lines[line_number - 1] = revised_line + newline
    revised = "".join(revised_lines)
    diff = "".join(difflib.unified_diff(
        text.splitlines(keepends=True), revised.splitlines(keepends=True),
        fromfile=f"a/{relative.as_posix()}", tofile=f"b/{relative.as_posix()}",
    ))
    return {
        "fingerprint": finding["fingerprint"], "repository": str(root), "file": relative.as_posix(),
        "line": line_number, "rule_id": finding["rule_id"], "recipe": "github-permissions-read-baseline",
        "diff": diff, "changes": [{"file": relative.as_posix(), "original": text, "replacement": revised}],
        "files": [relative.as_posix()],
    }


def preview_source_fix(finding: dict) -> dict:
    recipes = {
        "CODE-JS-INNERHTML": _preview_static_innerhtml,
        "CODE-PY-EVAL": _preview_python_literal_eval,
        "CODE-PY-SHELL": _preview_python_shell_false,
        "CI-GHA-PERSIST-CREDENTIALS": _preview_disable_persisted_credentials,
        "CI-GHA-WRITE-ALL": _preview_reduce_write_all,
    }
    recipe = recipes.get(finding.get("rule_id"))
    if not recipe:
        raise ValueError("No verified source-fix recipe exists for this rule")
    return recipe(finding)


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
