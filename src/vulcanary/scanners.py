from __future__ import annotations

import ast
import fnmatch
import hashlib
import io
import json
import math
import os
import re
import tokenize
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from .config import Config
from .models import Finding, Severity, relative_path


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    category: str
    remediation: str
    extensions: frozenset[str] = frozenset()


RULES = [
    Rule("SECRET-AWS-KEY", "AWS access key in source", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), Severity.CRITICAL, "secret", "Revoke the key, remove it from history, and use a secret manager."),
    Rule("SECRET-PRIVATE-KEY", "Private key in source", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL, "secret", "Remove and rotate the key; load it from a managed secret store."),
    Rule("SECRET-GITHUB-TOKEN", "GitHub token in source", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{30,255}\b"), Severity.CRITICAL, "secret", "Revoke the token and replace it with a short-lived credential."),
    Rule(
        "SECRET-HIGH-ENTROPY", "High-entropy credential in secret-like assignment",
        re.compile(
            r'''(?im)(?P<key>["']?(?:api[_-]?key|access[_-]?token|auth(?:orization)?|bearer[_-]?token|client[_-]?secret|credential|password|passwd|secret|token)["']?)\s*(?:=|:)\s*(?P<value>"[^"\r\n]{20,200}"|'[^'\r\n]{20,200}'|(?=[A-Za-z0-9_./+=:@-]{0,199}\d)[A-Za-z0-9_./+=:@-]{20,200})'''
        ),
        Severity.HIGH, "secret",
        "Rotate the credential, remove it from source and history, and load it from a managed secret store.",
    ),
    Rule("CODE-PY-EVAL", "Dynamic Python eval", re.compile(r"(?<![\w.])eval\s*\("), Severity.HIGH, "sast", "Avoid eval; parse and validate structured input explicitly.", frozenset({".py"})),
    Rule("CODE-PY-SHELL", "Shell command execution enabled", re.compile(r"subprocess\.(?:run|Popen|call)\s*\([^\n]*shell\s*=\s*True"), Severity.HIGH, "sast", "Pass an argument list with shell=False and validate all user-controlled values.", frozenset({".py"})),
    Rule("CODE-PY-PICKLE", "Unsafe Python deserialization", re.compile(r"(?<![\w.])pickle\.(?:load|loads)\s*\("), Severity.HIGH, "sast", "Do not deserialize untrusted pickle data; use a constrained data format such as JSON and validate its schema.", frozenset({".py"})),
    Rule("CODE-JS-EVAL", "Dynamic JavaScript eval", re.compile(r"(?<![\w.])eval\s*\("), Severity.HIGH, "sast", "Avoid eval and use a safe parser for the expected input format.", frozenset({".js", ".jsx", ".ts", ".tsx"})),
    Rule("CODE-JS-INNERHTML", "Potential DOM XSS sink", re.compile(r"\.innerHTML\s*="), Severity.MEDIUM, "sast", "Use textContent or sanitize trusted HTML with a maintained sanitizer.", frozenset({".js", ".jsx", ".ts", ".tsx"})),
    Rule("IAC-DOCKER-ROOT", "Container runs as root", re.compile(r"^\s*USER\s+(?:root|0)\s*$", re.I | re.M), Severity.MEDIUM, "iac", "Create and switch to an unprivileged user."),
    Rule("IAC-DOCKER-LATEST", "Container base image uses the latest tag", re.compile(r"^\s*FROM\s+\S+:latest(?:\s|$)", re.I | re.M), Severity.MEDIUM, "iac", "Pin the base image to a reviewed immutable digest or explicit version tag."),
    Rule("IAC-DOCKER-CURL-PIPE", "Container build pipes a download to a shell", re.compile(r"^\s*RUN\s+[^\n]*(?:curl|wget)[^\n]*\|\s*(?:sh|bash)\b", re.I | re.M), Severity.HIGH, "iac", "Download a pinned artifact, verify its checksum or signature, and execute it as a separate build step."),
    Rule("IAC-TF-PUBLIC-INGRESS", "Terraform allows ingress from the internet", re.compile(r'cidr_blocks\s*=\s*\[[^\]]*["\']0\.0\.0\.0/0["\']'), Severity.HIGH, "iac", "Restrict ingress CIDRs and ports to required sources."),
    Rule("IAC-TF-PUBLIC-ACL", "Terraform configures a public object-storage ACL", re.compile(r'\bacl\s*=\s*["\']public-(?:read|read-write)["\']'), Severity.HIGH, "iac", "Use a private ACL and grant narrowly scoped access through an explicit policy."),
    Rule("CI-GHA-WRITE-ALL", "GitHub Actions grants write-all permissions", re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.I | re.M), Severity.HIGH, "ci", "Declare the minimum required permissions and default unspecified scopes to none."),
    Rule("CI-GHA-MUTABLE-ACTION", "GitHub Action uses a mutable branch reference", re.compile(r"^\s*-?\s*uses\s*:\s*(?!\./)[^\s#]+@(?:main|master)\s*(?:#.*)?$", re.I | re.M), Severity.HIGH, "ci", "Pin third-party actions to a reviewed full commit SHA and let dependency automation propose updates."),
    Rule("CI-GHA-PERSIST-CREDENTIALS", "Checkout credentials remain available to later steps", re.compile(r"^\s*persist-credentials\s*:\s*true\s*(?:#.*)?$", re.I | re.M), Severity.MEDIUM, "ci", "Set persist-credentials to false unless later steps explicitly require GitHub token-backed pushes."),
]


def rules_for(config: Config | None = None) -> list[Rule]:
    custom = [] if config is None else [
        Rule(
            item["id"], item["title"], re.compile(item["pattern"], re.MULTILINE),
            Severity.parse(item["severity"]), item["category"], item["remediation"],
            frozenset(extension.lower() for extension in item.get("extensions", [])),
        )
        for item in config.custom_rules if item["status"] == "approved"
    ]
    return RULES + custom


def ruleset_manifest(config: Config | None = None) -> dict:
    rules = [{
        "id": rule.id, "title": rule.title, "severity": rule.severity.name.lower(),
        "category": rule.category, "extensions": sorted(rule.extensions),
        "engine": (
            "python_ast_with_regex_fallback" if rule.id in {"CODE-PY-EVAL", "CODE-PY-SHELL", "CODE-PY-PICKLE"}
            else "javascript_syntax_with_regex_fallback" if rule.id in {"CODE-JS-EVAL", "CODE-JS-INNERHTML"}
            else "contextual_entropy" if rule.id == "SECRET-HIGH-ENTROPY" else "regex"
        ),
        "pattern": rule.pattern.pattern, "pattern_flags": rule.pattern.flags,
        "remediation": rule.remediation,
    } for rule in sorted(rules_for(config), key=lambda item: item.id)]
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()
    return {"version": 1, "algorithm": "sha256", "digest": hashlib.sha256(canonical).hexdigest(), "rules": rules}


def ruleset_digest() -> str:
    return ruleset_manifest()["digest"]

INLINE_IGNORE_PATTERN = re.compile(
    r"^\s*(?://|#|<!--)\s*vulcanary:ignore\s+(?P<rule>[A-Z0-9-]+)\s+owner=(?P<owner>\S+)\s+expires=(?P<expires>\d{4}-\d{2}-\d{2})\s+--\s+(?P<justification>.+?)(?:\s*-->)?$"
)
INLINE_IGNORE_MARKER = re.compile(r"^\s*(?://|#|<!--)\s*vulcanary:ignore\b")


@dataclass(frozen=True)
class InlineSuppression:
    rule_id: str
    owner: str
    justification: str
    expires: str | None
    path: str
    line: int
    status: str
    error: str | None = None

    @property
    def fingerprint(self) -> str:
        value = f"inline\0{self.path}\0{self.line}\0{self.rule_id}".encode()
        return hashlib.sha256(value).hexdigest()[:20]

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint, "reason": "inline_ignore", "owner": self.owner,
            "justification": self.justification, "expires": self.expires, "status": self.status,
            "scope": "inline", "rule_id": self.rule_id, "path": self.path, "line": self.line,
        }


def _parse_inline_suppression(line_text: str, path: str, line: int, today: date | None = None) -> InlineSuppression | None:
    if not INLINE_IGNORE_MARKER.search(line_text):
        return None
    match = INLINE_IGNORE_PATTERN.search(line_text.strip())
    if not match:
        return InlineSuppression("unknown", "unmanaged", "Invalid inline exception annotation.", None, path, line, "invalid", "Required format is incomplete")
    values = match.groupdict()
    owner = values["owner"].strip()
    justification = values["justification"].strip()
    if len(owner) < 2 or len(justification) < 10:
        return InlineSuppression(values["rule"], owner or "unmanaged", justification or "Missing justification.", values["expires"], path, line, "invalid", "Owner and a justification of at least 10 characters are required")
    try:
        expiry = date.fromisoformat(values["expires"])
    except ValueError:
        return InlineSuppression(values["rule"], owner, justification, values["expires"], path, line, "invalid", "Expiration must be a valid ISO date")
    current = today or date.today()
    status = "expired" if expiry < current else "expiring" if (expiry - current).days <= 14 else "active"
    return InlineSuppression(values["rule"], owner, justification, values["expires"], path, line, status)


def _supports_inline_suppressions(path: Path) -> bool:
    return path.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".tf"} or path.name.lower() in {"dockerfile", "containerfile"}


def inline_suppression_register(root: Path, config: Config, today: date | None = None) -> list[dict]:
    records = []
    for path in iter_files(root, config):
        if not _supports_inline_suppressions(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = relative_path(path, root)
        records.extend(record.to_dict() for number, text in enumerate(lines, 1) if (record := _parse_inline_suppression(text, rel, number, today)))
    return records


def is_excluded(path: str | Path, config: Config, root: Path | None = None) -> bool:
    candidate = Path(path)
    rel = relative_path(candidate, root) if root is not None else candidate.as_posix().lstrip("./")
    return any(
        fnmatch.fnmatch(rel, pattern)
        or fnmatch.fnmatch(rel, f"*/{pattern}")
        or fnmatch.fnmatch(f"{rel}/", pattern)
        or fnmatch.fnmatch(f"{rel}/", f"*/{pattern}")
        or fnmatch.fnmatch(candidate.name, pattern)
        for pattern in config.exclude
    )


def iter_files(root: Path, config: Config) -> Iterable[Path]:
    def excluded(path: Path) -> bool:
        return is_excluded(path, config, root)

    for directory, names, files in os.walk(root, topdown=True):
        parent = Path(directory)
        names[:] = [name for name in names if not excluded(parent / name)]
        for name in files:
            path = parent / name
            if excluded(path):
                continue
            try:
                if path.stat().st_size > config.max_file_bytes:
                    continue
            except OSError:
                continue
            yield path


_SECRET_PLACEHOLDERS = (
    "changeme", "dummy", "example", "fake", "not-a-real", "not_a_real", "placeholder",
    "redacted", "replace-me", "replace_me", "sample", "test-token", "your-api", "your_api",
)


def _entropy_secret_candidate(match: re.Match[str], path: str = "") -> tuple[bool, float]:
    value = match.group("value").strip().strip("\"'")
    value = re.sub(r"^(?:bearer|basic)\s+", "", value, flags=re.I)
    lowered = value.lower()
    normalized_path = "/" + path.lower().replace("\\", "/")
    filename = Path(path).name.lower()
    fixture_path = (
        any(part in normalized_path for part in ("/test/", "/tests/", "/fixtures/", "/examples/", "/testdata/"))
        or any(marker in filename for marker in (".example", ".sample", ".template"))
    )
    if (
        fixture_path
        or any(marker in lowered for marker in _SECRET_PLACEHOLDERS)
        or any(marker in value for marker in ("${", "{{", "<%", "process.env", "os.environ"))
        or lowered.startswith(("http://", "https://", "file://"))
        or re.fullmatch(r"[0-9a-f]{32,128}", value, re.I)
        or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value, re.I)
    ):
        return False, 0.0
    counts = Counter(value)
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
    classes = sum(bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    accepted = entropy >= 3.7 and len(counts) / len(value) >= 0.35 and classes >= 2
    return accepted, entropy


def _entropy_match_has_assignment_context(text: str, key_end: int) -> bool:
    line_start = text.rfind("\n", 0, key_end) + 1
    prefix = text[line_start:key_end]
    stripped = prefix.lstrip()
    if stripped.startswith(("#", "//", "*", "<!--")):
        return False
    quote = None
    escaped = False
    for character in prefix:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote is not None:
            if character == quote:
                quote = None
        elif character in {"\"", "'", "`"}:
            quote = character
    return quote is None


def _python_non_code_spans(text: str) -> list[tuple[int, int]]:
    lines = text.splitlines(keepends=True)
    offsets = []
    total = 0
    for line in lines:
        offsets.append(total)
        total += len(line)

    def absolute(position: tuple[int, int]) -> int:
        line, column = position
        return (offsets[line - 1] if 0 < line <= len(offsets) else len(text)) + column

    spans = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type in {tokenize.STRING, tokenize.COMMENT}:
                spans.append((absolute(token.start), absolute(token.end)))
    except (IndentationError, tokenize.TokenError):
        pass
    return spans


def _is_static_inner_html_assignment(text: str, match_end: int) -> bool:
    """Treat one quoted literal with no template interpolation as data, not an XSS flow."""
    index = match_end
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] not in {'"', "'", "`"}:
        return False
    quote = text[index]
    index += 1
    escaped = False
    while index < len(text):
        character = text[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote == "`" and text.startswith("${", index):
            return False
        elif character == quote:
            index += 1
            break
        index += 1
    else:
        return False
    while index < len(text) and text[index] in " \t":
        index += 1
    if index < len(text) and text[index] == ";":
        index += 1
    while index < len(text) and text[index] in " \t":
        index += 1
    return index >= len(text) or text[index] in "\r\n" or text.startswith("//", index)


_PYTHON_AST_RULES = frozenset({"CODE-PY-EVAL", "CODE-PY-SHELL", "CODE-PY-PICKLE"})
_JAVASCRIPT_SYNTAX_RULES = frozenset({"CODE-JS-EVAL", "CODE-JS-INNERHTML"})


def _javascript_code_mask(text: str) -> str | None:
    """Preserve executable character offsets while blanking JS/TS literals and comments."""
    masked = list(text)
    index = 0
    significant = ""

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    def quoted_end(start: int, quote: str) -> int | None:
        cursor = start + 1
        escaped = False
        while cursor < len(text):
            if escaped:
                escaped = False
            elif text[cursor] == "\\":
                escaped = True
            elif text[cursor] == quote:
                return cursor + 1
            cursor += 1
        return None

    def expression_end(start: int) -> int | None:
        cursor = start
        depth = 1
        while cursor < len(text):
            character = text[cursor]
            following = text[cursor + 1] if cursor + 1 < len(text) else ""
            if character in {'"', "'"}:
                cursor = quoted_end(cursor, character) or len(text)
                continue
            if character == "`":
                parsed = template_end(cursor)
                if parsed is None:
                    return None
                cursor = parsed[0]
                continue
            if character == "/" and following == "/":
                line_end = text.find("\n", cursor + 2)
                cursor = len(text) if line_end < 0 else line_end
                continue
            if character == "/" and following == "*":
                comment_end = text.find("*/", cursor + 2)
                if comment_end < 0:
                    return None
                cursor = comment_end + 2
                continue
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return cursor
            cursor += 1
        return None

    def template_end(start: int) -> tuple[int, list[tuple[int, int]]] | None:
        cursor = start + 1
        expressions = []
        escaped = False
        while cursor < len(text):
            character = text[cursor]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "`":
                return cursor + 1, expressions
            elif character == "$" and cursor + 1 < len(text) and text[cursor + 1] == "{":
                end = expression_end(cursor + 2)
                if end is None:
                    return None
                expressions.append((cursor + 2, end))
                cursor = end
            cursor += 1
        return None

    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if index == 0 and character == "#" and following == "!":
            end = text.find("\n", index + 2)
            index = len(text) if end < 0 else end
            blank(0, index)
            continue
        if character in {'"', "'"}:
            start = index
            end = quoted_end(start, character)
            if end is None:
                return None
            index = end
            blank(start, index)
            significant = "literal"
            continue
        if character == "`":
            start = index
            parsed = template_end(start)
            if parsed is None:
                return None
            index, expressions = parsed
            blank(start, index)
            for expression_start, expression_stop in expressions:
                expression_mask = _javascript_code_mask(text[expression_start:expression_stop])
                if expression_mask is None:
                    return None
                masked[expression_start:expression_stop] = expression_mask
            significant = "literal"
            continue
        if character == "/" and following == "/":
            start = index
            end = text.find("\n", index + 2)
            index = len(text) if end < 0 else end
            blank(start, index)
            continue
        if character == "/" and following == "*":
            start = index
            end = text.find("*/", index + 2)
            if end < 0:
                return None
            index = end + 2
            blank(start, index)
            continue
        regex_context = (
            not significant
            or significant[-1:] in "=(:,[!&|?{};"
            or significant.endswith("=>")
            or re.search(r"(?:return|case|throw|yield|await)$", significant) is not None
        )
        if character == "/" and regex_context:
            start = index
            index += 1
            escaped = False
            in_class = False
            while index < len(text):
                current = text[index]
                if current in "\r\n":
                    return None
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == "[":
                    in_class = True
                elif current == "]":
                    in_class = False
                elif current == "/" and not in_class:
                    index += 1
                    while index < len(text) and text[index].isalpha():
                        index += 1
                    blank(start, index)
                    break
                index += 1
            else:
                return None
            significant = "literal"
            continue
        if not character.isspace():
            significant = (significant + character)[-16:]
        index += 1
    return "".join(masked)


def _javascript_syntax_matches(text: str) -> dict[str, list[tuple[int, str]]] | None:
    masked = _javascript_code_mask(text)
    if masked is None:
        return None
    matches: dict[str, list[tuple[int, str]]] = {rule_id: [] for rule_id in _JAVASCRIPT_SYNTAX_RULES}
    def declaration(start: int, end: int) -> bool:
        line_start = masked.rfind("\n", 0, start) + 1
        if re.search(r"\b(?:declare\s+)?(?:async\s+)?function\s*\*?\s*$", masked[line_start:start]):
            return True
        depth = 1
        index = end
        while index < len(masked) and depth:
            if masked[index] == "(":
                depth += 1
            elif masked[index] == ")":
                depth -= 1
            index += 1
        while index < len(masked) and masked[index].isspace():
            index += 1
        return depth == 0 and index < len(masked) and masked[index] in "{:"

    eval_spans: list[tuple[int, int, str]] = []
    for pattern in (
        re.compile(r"(?<![\w.$])eval\s*\("),
        re.compile(r"\b(?:globalThis|window|self)\s*\.\s*eval\s*\("),
    ):
        eval_spans.extend(
            (match.start(), match.end(), match.group(0))
            for match in pattern.finditer(masked) if not declaration(match.start(), match.end())
        )
    brace_depths = []
    brace_depth = 0
    for character in masked:
        brace_depths.append(brace_depth)
        if character == "{":
            brace_depth += 1
        elif character == "}":
            brace_depth = max(0, brace_depth - 1)
    aliases: dict[str, list[tuple[int, int]]] = {}
    for match in re.finditer(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:(?:globalThis|window|self)\s*\.\s*)?eval\s*;?",
            masked,
        ):
        aliases.setdefault(match.group(1), []).append((match.end(), brace_depths[match.start()]))
    for alias, declarations in aliases.items():
        pattern = re.compile(rf"(?<![\w.$]){re.escape(alias)}\s*\(")
        eval_spans.extend(
            (match.start(), match.end(), f"{alias}(")
            for match in pattern.finditer(masked)
            if any(match.start() >= declared_at and brace_depths[match.start()] == depth for declared_at, depth in declarations)
            and not declaration(match.start(), match.end())
        )
    eval_rule = next(rule for rule in RULES if rule.id == "CODE-JS-EVAL")
    for start, end, fallback in sorted(set(eval_spans)):
        legacy = eval_rule.pattern.search(text, start, end)
        evidence = legacy.group(0) if legacy else fallback.replace("\n", " ")[:120]
        matches["CODE-JS-EVAL"].append((text.count("\n", 0, start) + 1, evidence))

    inner_rule = next(rule for rule in RULES if rule.id == "CODE-JS-INNERHTML")
    for match in re.finditer(r"\.\s*innerHTML\s*=", masked):
        if _is_static_inner_html_assignment(text, match.end()):
            continue
        legacy = inner_rule.pattern.search(text, match.start(), match.end())
        evidence = legacy.group(0) if legacy else ".innerHTML ="
        matches["CODE-JS-INNERHTML"].append((text.count("\n", 0, match.start()) + 1, evidence))
    return matches


def _python_ast_matches(text: str) -> dict[str, list[tuple[int, str]]] | None:
    """Return confirmed Python call sites, or None when regex fallback is required."""
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError):
        return None

    parents = {child: parent for parent in ast.walk(module) for child in ast.iter_child_nodes(parent)}
    scope_types = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    scopes: dict[ast.AST, dict[str, object]] = {
        node: {"subprocess_modules": set(), "pickle_modules": set(), "subprocess_functions": {}, "pickle_functions": {}}
        for node in ast.walk(module) if isinstance(node, scope_types)
    }
    scopes[module]["subprocess_modules"] = {"subprocess"}
    scopes[module]["pickle_modules"] = {"pickle"}
    matches: dict[str, list[tuple[int, str]]] = {rule_id: [] for rule_id in _PYTHON_AST_RULES}

    def evidence(rule_id: str, node: ast.Call, fallback: str) -> str:
        segment = ast.get_source_segment(text, node) or ""
        rule = next(item for item in RULES if item.id == rule_id)
        legacy = rule.pattern.search(segment)
        return legacy.group(0).replace("\n", " ")[:120] if legacy else fallback

    def containing_scopes(node: ast.AST) -> list[dict[str, object]]:
        found = []
        current = node
        while current in parents:
            current = parents[current]
            if current in scopes:
                found.append(scopes[current])
        return found

    for node in ast.walk(module):
        containing = containing_scopes(node)
        scope = containing[0] if containing else scopes[module]
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    scope["subprocess_modules"].add(alias.asname or alias.name)
                elif alias.name in {"pickle", "_pickle"}:
                    scope["pickle_modules"].add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                for alias in node.names:
                    if alias.name in {"run", "Popen", "call"}:
                        scope["subprocess_functions"][alias.asname or alias.name] = alias.name
            elif node.module in {"pickle", "_pickle"}:
                for alias in node.names:
                    if alias.name in {"load", "loads"}:
                        scope["pickle_functions"][alias.asname or alias.name] = alias.name

    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        active_scopes = containing_scopes(node)
        subprocess_modules = set().union(*(scope["subprocess_modules"] for scope in active_scopes))
        pickle_modules = set().union(*(scope["pickle_modules"] for scope in active_scopes))
        subprocess_functions = {name: value for scope in reversed(active_scopes) for name, value in scope["subprocess_functions"].items()}
        pickle_functions = {name: value for scope in reversed(active_scopes) for name, value in scope["pickle_functions"].items()}
        function = node.func
        if isinstance(function, ast.Name) and function.id == "eval":
            matches["CODE-PY-EVAL"].append((node.lineno, evidence("CODE-PY-EVAL", node, "eval(")))

        function_name = None
        module_name = None
        if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            module_name, function_name = function.value.id, function.attr
        elif isinstance(function, ast.Name):
            function_name = subprocess_functions.get(function.id) or pickle_functions.get(function.id)

        is_subprocess = (
            function_name in {"run", "Popen", "call"}
            and (module_name in subprocess_modules or (isinstance(function, ast.Name) and function.id in subprocess_functions))
        )
        shell_true = any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords
        )
        if is_subprocess and shell_true:
            matches["CODE-PY-SHELL"].append((node.lineno, evidence("CODE-PY-SHELL", node, f"{function_name}(..., shell=True)")))

        is_pickle = (
            function_name in {"load", "loads"}
            and (module_name in pickle_modules or (isinstance(function, ast.Name) and function.id in pickle_functions))
        )
        if is_pickle:
            matches["CODE-PY-PICKLE"].append((node.lineno, evidence("CODE-PY-PICKLE", node, f"{function_name}(")))
    return matches


def scan(root: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    rules = rules_for(config)
    for path in iter_files(root, config):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = relative_path(path, root)
        lines = text.splitlines()
        python_ast_matches = _python_ast_matches(text) if path.suffix.lower() == ".py" else None
        javascript_syntax_matches = _javascript_syntax_matches(text) if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"} else None
        python_non_code_spans: list[tuple[int, int]] | None = None
        annotations = {
            number: record for number, line_text in enumerate(lines, 1)
            if (record := _parse_inline_suppression(line_text, rel, number))
        } if _supports_inline_suppressions(path) else {}
        for record in annotations.values():
            if record.status not in {"invalid", "expired", "expiring"}:
                continue
            severity = Severity.HIGH if record.status in {"invalid", "expired"} else Severity.MEDIUM
            title = {"invalid": "Invalid inline security exception", "expired": "Inline security exception has expired", "expiring": "Inline security exception expires soon"}[record.status]
            findings.append(Finding(
                f"GOV-INLINE-IGNORE-{record.status.upper()}", title,
                record.error or f"The inline exception for {record.rule_id} is {record.status}.", severity,
                "governance", rel, record.line, record.rule_id,
                "Complete or renew the exception after review, or remediate the underlying finding.",
                "vulcanary-governance", record.to_dict(),
            ))
        for rule in rules:
            if rule.id in config.ignored_rules:
                continue
            if rule.extensions and path.suffix.lower() not in rule.extensions:
                continue
            if rule.id.startswith("IAC-DOCKER-") and path.name.lower() not in {"dockerfile", "containerfile"}:
                continue
            if rule.id.startswith("IAC-TF-") and path.suffix.lower() != ".tf":
                continue
            if rule.id.startswith("CI-GHA-") and not (path.suffix.lower() in {".yml", ".yaml"} and ".github/workflows/" in f"/{rel}"):
                continue
            if rule.id in _PYTHON_AST_RULES and python_ast_matches is not None:
                for line, evidence in python_ast_matches[rule.id]:
                    candidates = [annotations[number] for number in (line - 1, line) if number in annotations]
                    if any(record.rule_id == rule.id and record.status in {"active", "expiring"} for record in candidates):
                        continue
                    finding = Finding(rule.id, rule.title, f"Matched security rule {rule.id}.", rule.severity, rule.category, rel, line, evidence, rule.remediation)
                    if not config.is_suppressed(finding.fingerprint):
                        findings.append(finding)
                continue
            if rule.id in _JAVASCRIPT_SYNTAX_RULES and javascript_syntax_matches is not None:
                for line, evidence in javascript_syntax_matches[rule.id]:
                    candidates = [annotations[number] for number in (line - 1, line) if number in annotations]
                    if any(record.rule_id == rule.id and record.status in {"active", "expiring"} for record in candidates):
                        continue
                    finding = Finding(rule.id, rule.title, f"Matched security rule {rule.id}.", rule.severity, rule.category, rel, line, evidence, rule.remediation)
                    if not config.is_suppressed(finding.fingerprint):
                        findings.append(finding)
                continue
            for match in rule.pattern.finditer(text):
                if rule.id == "CODE-JS-INNERHTML" and _is_static_inner_html_assignment(text, match.end()):
                    continue
                entropy = None
                if rule.id == "SECRET-HIGH-ENTROPY":
                    if path.suffix.lower() == ".py":
                        if python_non_code_spans is None:
                            python_non_code_spans = _python_non_code_spans(text)
                        if any(start <= match.start() and match.end() <= end for start, end in python_non_code_spans):
                            continue
                    if not _entropy_match_has_assignment_context(text, match.end("key")):
                        continue
                    accepted, entropy = _entropy_secret_candidate(match, rel)
                    if not accepted:
                        continue
                    value = match.group("value").strip().strip("\"'")
                    if any(item.id != rule.id and item.category == "secret" and item.pattern.search(value) for item in rules):
                        continue
                line = text.count("\n", 0, match.start()) + 1
                candidates = [annotations[number] for number in (line - 1, line) if number in annotations]
                if any(record.rule_id == rule.id and record.status in {"active", "expiring"} for record in candidates):
                    continue
                evidence = match.group(0).replace("\n", " ")[:120]
                if rule.category == "secret":
                    evidence = "[redacted]"
                metadata = {"confidence": "high", "detector": "contextual_entropy", "entropy": round(entropy, 2)} if entropy is not None else {}
                finding = Finding(rule.id, rule.title, f"Matched security rule {rule.id}.", rule.severity, rule.category, rel, line, evidence, rule.remediation, metadata=metadata)
                if not config.is_suppressed(finding.fingerprint):
                    findings.append(finding)
    return sorted({item.fingerprint: item for item in findings}.values(), key=lambda f: (-int(f.severity), f.path, f.line))
