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
_TOOLING_PACKAGES = {
    "babel-jest", "babel-plugin-istanbul", "@istanbuljs/load-nyc-config", "xcode",
    "jest", "eslint", "typescript", "metro", "webpack", "vite", "rollup",
    "@expo/config", "@expo/config-plugins", "@expo/cli",
}
_SEVERITY_PRIORITY = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}


def _npm_root(specifier: str) -> str | None:
    if specifier.startswith((".", "/", "#")):
        return None
    parts = specifier.split("/")
    return "/".join(parts[:2]) if specifier.startswith("@") and len(parts) > 1 else parts[0]


def _normalized_python(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _path_contains_tooling(paths: list[list[str]]) -> bool:
    for path in paths:
        for label in path[1:-1]:
            name = label.rsplit("@", 1)[0] if "@" in label[1:] else label
            if name.lower() in _TOOLING_PACKAGES:
                return True
    return False


def remediation_priority(finding: Finding, metadata: dict) -> dict:
    score = _SEVERITY_PRIORITY[finding.severity.name.lower()]
    usage = metadata.get("usage", {}).get("classification", "unknown")
    factors = [f"{finding.severity.name.lower()} advisory severity"]
    adjustments = {
        "source_observed": (15, "scanner matched repository source"),
        "direct_application_import_observed": (15, "direct application import observed"),
        "runtime_parent_observed": (10, "runtime parent import observed"),
        "tooling_path_via_runtime_parent": (-25, "build or test tooling path"),
        "development_observed": (-20, "development dependency path"),
        "development_not_observed": (-25, "development-only path not statically observed"),
        "runtime_not_observed": (-5, "runtime path not statically observed"),
    }
    adjustment, factor = adjustments.get(usage, (0, "execution context remains unknown"))
    score += adjustment
    factors.append(factor)
    if metadata.get("fix_eligible"):
        score += 5
        factors.append("safe automatic fix available")
    if finding.category == "dependency" and not metadata.get("fixed_version"):
        score -= 5
        factors.append("no patched release identified")
    score = max(0, min(100, score))
    level = "urgent" if score >= 85 else "high_priority" if score >= 65 else "planned" if score >= 35 else "monitor_upstream"
    labels = {"urgent": "Urgent", "high_priority": "High priority", "planned": "Planned", "monitor_upstream": "Monitor upstream"}
    return {
        "level": level,
        "label": labels[level],
        "score": score,
        "reason": "; ".join(factors) + ". Severity remains unchanged.",
        "factors": factors,
    }


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
            metadata = dict(finding.metadata)
            metadata["usage"] = {
                "classification": "source_observed",
                "reason": "The scanner matched repository source or configuration directly.",
            }
            metadata["recommendation"] = {
                "action": "review_source_fix",
                "reason": finding.remediation or "Review the matched source in context, apply the narrowest safe fix, run project checks, and rescan.",
            }
            metadata["priority"] = remediation_priority(finding, metadata)
            analyzed.append(replace(finding, metadata=metadata))
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
        scopes = metadata.get("parent_scopes", {})
        matched_scopes = {scopes.get(name) for name in matched if scopes.get(name)}
        tooling_path = _path_contains_tooling(metadata.get("dependency_paths", []))
        if matched and metadata.get("direct"):
            usage = "direct_application_import_observed"
            usage_reason = "The vulnerable direct dependency is imported by scanned application source."
        elif matched and tooling_path:
            usage = "tooling_path_via_runtime_parent"
            usage_reason = "An imported runtime parent introduces the package through a build or test tooling path; production execution is not established."
        elif matched and "runtime" in matched_scopes:
            usage = "runtime_parent_observed"
            usage_reason = "An introducing runtime dependency is imported, but static analysis does not prove the vulnerable transitive code executes in production."
        elif matched and matched_scopes == {"development"}:
            usage = "development_observed"
            usage_reason = "Only an introducing development dependency was observed in scanned source."
        elif "runtime" in set(scopes.values()):
            usage = "runtime_not_observed"
            usage_reason = "The package is reachable from a runtime dependency, but no static import was observed."
        elif scopes and set(scopes.values()) == {"development"}:
            usage = "development_not_observed"
            usage_reason = "The package is reachable only from declared development dependencies; dynamic or build-time execution remains possible."
        else:
            usage = "unknown"
            usage_reason = "Vulcanary cannot reliably classify this dependency as runtime-only or development-only."
        metadata["usage"] = {"classification": usage, "reason": usage_reason}

        parents = list(metadata.get("parent_packages", []))
        fixed = metadata.get("fixed_version")
        if metadata.get("fix_eligible"):
            action = "safe_direct_upgrade"
            recommendation = f"Upgrade {package} to {fixed}; verify project checks and rescan."
        elif not fixed:
            action = "monitor_upstream"
            recommendation = "No patched release is identified. Monitor the advisory and upstream dependency while reviewing compensating controls."
        elif not metadata.get("direct") and "expo" in parents:
            action = "evaluate_platform_upgrade"
            recommendation = "Evaluate the compatible Expo platform set in isolation; avoid forcing an unscoped transitive override."
        elif not metadata.get("direct") and parents:
            action = "evaluate_parent_upgrade"
            recommendation = f"Evaluate upgrades for {', '.join(parents)} in isolation, then rescan the resolved lockfile."
        elif metadata.get("direct"):
            action = "review_major_upgrade"
            recommendation = f"Review the breaking changes required to move {package} to {fixed}, test, and rescan."
        else:
            action = "trace_upstream"
            recommendation = "Trace the introducing package and prefer an upstream upgrade over a global transitive override."
        metadata["recommendation"] = {"action": action, "reason": recommendation}
        metadata["priority"] = remediation_priority(finding, metadata)
        analyzed.append(replace(finding, metadata=metadata))
    return analyzed
