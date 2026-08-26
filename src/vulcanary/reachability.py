from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from .config import Config
from .models import Finding
from .scanners import iter_files


_JS_IMPORT = re.compile(
    r"(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s*)['\"]([^'\"]+)['\"]"
)
_PY_FROM = re.compile(r"(?m)^\s*from\s+([A-Za-z_]\w*(?:\.\w+)*)\s+import\b")
_PY_IMPORT = re.compile(r"(?m)^\s*import\s+([^\n#]+)")
_SOURCE_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"}


def _npm_root(specifier: str) -> str | None:
    if specifier.startswith((".", "/", "#")):
        return None
    parts = specifier.split("/")
    return "/".join(parts[:2]) if specifier.startswith("@") and len(parts) > 1 else parts[0]


def _normalized_python(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def observed_imports(root: Path, config: Config) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    npm: dict[str, set[str]] = {}
    python: dict[str, set[str]] = {}
    for path in iter_files(root, config):
        if path.suffix.lower() not in _SOURCE_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
            relative = path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        if path.suffix.lower() == ".py":
            names = [match.group(1).split(".", 1)[0] for match in _PY_FROM.finditer(text)]
            for match in _PY_IMPORT.finditer(text):
                names.extend(item.strip().split(" as ", 1)[0].split(".", 1)[0] for item in match.group(1).split(","))
            for name in names:
                if name:
                    python.setdefault(_normalized_python(name), set()).add(relative)
        else:
            for match in _JS_IMPORT.finditer(text):
                name = _npm_root(match.group(1))
                if name:
                    npm.setdefault(name.lower(), set()).add(relative)
    return npm, python


def analyze_reachability(root: Path, findings: list[Finding], config: Config) -> list[Finding]:
    npm_imports, python_imports = observed_imports(root, config)
    analyzed = []
    for finding in findings:
        if finding.category != "dependency":
            analyzed.append(finding)
            continue
        metadata = dict(finding.metadata)
        package = str(metadata.get("package", ""))
        ecosystem = metadata.get("ecosystem")
        paths: set[str] = set()
        matched: list[str] = []
        if ecosystem == "npm":
            candidates = [package] if metadata.get("direct") else list(metadata.get("parent_packages", []))
            for candidate in candidates:
                evidence = npm_imports.get(candidate.lower(), set())
                if evidence:
                    matched.append(candidate)
                    paths.update(evidence)
        elif ecosystem == "PyPI":
            normalized = _normalized_python(package)
            evidence = python_imports.get(normalized, set())
            if evidence:
                matched.append(package)
                paths.update(evidence)
        if matched:
            status = "direct_import_observed" if metadata.get("direct") or ecosystem == "PyPI" else "parent_import_observed"
            reason = "The vulnerable package is imported by application source." if status == "direct_import_observed" else "An introducing direct dependency is imported by application source."
        else:
            status = "not_observed"
            reason = "No static import was observed; the package may still be reachable through dynamic loading, tooling, runtime plugins, or indirect execution."
        metadata["reachability"] = {
            "status": status,
            "reason": reason,
            "matched_packages": sorted(matched),
            "evidence_paths": sorted(paths)[:20],
        }
        analyzed.append(replace(finding, metadata=metadata))
    return analyzed
