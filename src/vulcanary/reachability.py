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
_JAVA_IMPORT = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*;?")
_CSHARP_USING = re.compile(r"(?m)^\s*(?:global\s+)?using\s+(?:static\s+)?(?:[A-Za-z_]\w*\s*=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;")
_GO_SINGLE_IMPORT = re.compile(r'(?m)^\s*import\s+(?:[._A-Za-z]\w*\s+)?"([^"\r\n]+)"')
_GO_IMPORT_BLOCK = re.compile(r"(?ms)^\s*import\s*\((.*?)^\s*\)")
_GO_BLOCK_PATH = re.compile(r'(?m)^\s*(?:[._A-Za-z]\w*\s+)?"([^"\r\n]+)"')
_RUST_USE = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:r#)?([A-Za-z_]\w*)\s*(?:::|;)")
_RUST_EXTERN = re.compile(r"(?m)^\s*extern\s+crate\s+(?:r#)?([A-Za-z_]\w*)\s*;")
_RUBY_REQUIRE = re.compile(r"(?m)^\s*require\s*(?:\(?\s*)['\"]([^'\"]+)['\"]")
_SOURCE_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java", ".kt", ".cs", ".go", ".rs", ".rb"}
_REACHABILITY_ECOSYSTEMS = {"npm", "PyPI", "Maven", "NuGet", "Go", "crates.io", "RubyGems"}
_TOOLING_PACKAGES = {
    "babel-jest", "babel-plugin-istanbul", "@istanbuljs/load-nyc-config", "xcode",
    "jest", "eslint", "typescript", "metro", "webpack", "vite", "rollup",
    "@expo/config", "@expo/config-plugins", "@expo/cli",
}
_SEVERITY_PRIORITY = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5, "unknown": 0}
_DEPLOYMENT_FILES = {"vercel.json", "netlify.toml", "fly.toml", "render.yaml", "render.yml", "app.yaml", "serverless.yml", "serverless.yaml", "dockerfile", "containerfile"}
_ROUTE_PATH = re.compile(r"(?:^|/)(?:api|routes?|pages/api|app/api|server|functions?)(?:/|$)", re.I)


def _npm_root(specifier: str) -> str | None:
    if specifier.startswith((".", "/", "#")):
        return None
    parts = specifier.split("/")
    return "/".join(parts[:2]) if specifier.startswith("@") and len(parts) > 1 else parts[0]


def _normalized_python(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _c_family_code(text: str, preserve_strings: bool = False) -> str:
    """Blank comments and, unless requested, literals while preserving offsets and lines."""
    masked = list(text)
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if quote is not None:
            if not preserve_strings and character not in "\r\n":
                masked[index] = " "
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {'"', "'", "`"}:
            quote = character
            if not preserve_strings:
                masked[index] = " "
            index += 1
            continue
        if character == "/" and following == "/":
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            for offset in range(index, end):
                masked[offset] = " "
            index = end
            continue
        if character == "/" and following == "*":
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            for offset in range(index, end):
                if masked[offset] not in "\r\n":
                    masked[offset] = " "
            index = end
            continue
        index += 1
    return "".join(masked)


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
        "dependency_import_observed": (10, "dependency namespace import observed"),
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
    exposure = metadata.get("exposure", {}).get("classification")
    if exposure == "route_candidate_with_deploy_config":
        score += 10
        factors.append("route-like source and deployment configuration observed")
    elif exposure == "route_candidate":
        score += 5
        factors.append("route-like source path observed")
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


def _deployment_context(root: Path, config: Config) -> list[str]:
    assets = []
    for path in iter_files(root, config):
        relative = path.resolve().relative_to(root.resolve()).as_posix()
        if path.name.lower() in _DEPLOYMENT_FILES or path.suffix.lower() == ".tf" or relative.startswith(".github/workflows/"):
            assets.append(relative)
    return sorted(set(assets))[:30]


def _exposure_context(finding: Finding, metadata: dict, deployment_assets: list[str]) -> dict:
    evidence_paths = list(metadata.get("reachability", {}).get("evidence_paths", [])) or [finding.path]
    route_paths = sorted(path for path in evidence_paths if _ROUTE_PATH.search(path))[:20]
    if route_paths and deployment_assets:
        classification = "route_candidate_with_deploy_config"
        reason = "Route-like source and deployment configuration were observed. This raises exposure priority but does not prove the route is publicly reachable."
    elif route_paths:
        classification = "route_candidate"
        reason = "A route-like source path was observed. Public deployment and reachability are not established."
    elif deployment_assets:
        classification = "deployment_context_only"
        reason = "Deployment configuration exists, but this finding was not correlated with a route-like source path. Exposure remains unknown."
    else:
        classification = "unknown"
        reason = "No reliable route or deployment evidence was correlated. Absence of evidence is not evidence that the finding is unreachable."
    return {"classification": classification, "reason": reason, "route_paths": route_paths, "deployment_assets": deployment_assets}


def _all_observed_imports(root: Path, config: Config) -> dict[str, dict[str, set[str]]]:
    observed: dict[str, dict[str, set[str]]] = {
        "npm": {}, "pypi": {}, "maven": {}, "nuget": {}, "go": {}, "crates.io": {}, "rubygems": {},
    }

    def add(ecosystem: str, name: str, relative: str) -> None:
        if name:
            observed[ecosystem].setdefault(name.lower(), set()).add(relative)

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
                add("pypi", _normalized_python(name), relative)
        elif path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            for match in _JS_IMPORT.finditer(text):
                name = _npm_root(match.group(1))
                if name:
                    add("npm", name, relative)
        elif path.suffix.lower() in {".java", ".kt"}:
            for match in _JAVA_IMPORT.finditer(_c_family_code(text)):
                add("maven", match.group(1), relative)
        elif path.suffix.lower() == ".cs":
            for match in _CSHARP_USING.finditer(_c_family_code(text)):
                add("nuget", match.group(1), relative)
        elif path.suffix.lower() == ".go":
            code = _c_family_code(text, preserve_strings=True)
            for match in _GO_SINGLE_IMPORT.finditer(code):
                add("go", match.group(1), relative)
            for block in _GO_IMPORT_BLOCK.finditer(code):
                for match in _GO_BLOCK_PATH.finditer(block.group(1)):
                    add("go", match.group(1), relative)
        elif path.suffix.lower() == ".rs":
            for pattern in (_RUST_USE, _RUST_EXTERN):
                for match in pattern.finditer(_c_family_code(text)):
                    add("crates.io", match.group(1).replace("_", "-"), relative)
        elif path.suffix.lower() == ".rb":
            for match in _RUBY_REQUIRE.finditer(text):
                add("rubygems", match.group(1).split("/", 1)[0], relative)
    return observed


def observed_imports(root: Path, config: Config) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return the original npm/Python import views for API compatibility."""
    observed = _all_observed_imports(root, config)
    return observed["npm"], observed["pypi"]


def _correlated_imports(ecosystem: str, package: str, observed: dict[str, dict[str, set[str]]]) -> set[str]:
    index = observed.get(ecosystem.lower(), {})
    normalized = package.lower()
    if ecosystem == "PyPI":
        return set(index.get(_normalized_python(package), set()))
    if ecosystem == "Maven" and ":" in normalized:
        group, _artifact = normalized.split(":", 1)
        return {path for imported, paths in index.items() if imported == group or imported.startswith(group + ".") for path in paths}
    if ecosystem == "NuGet":
        return {path for imported, paths in index.items() if imported == normalized or imported.startswith(normalized + ".") for path in paths}
    if ecosystem == "Go":
        return {path for imported, paths in index.items() if imported == normalized or imported.startswith(normalized + "/") for path in paths}
    key = normalized.replace("_", "-") if ecosystem == "crates.io" else normalized
    return set(index.get(key, set()))


def analyze_reachability(root: Path, findings: list[Finding], config: Config) -> list[Finding]:
    imports = _all_observed_imports(root, config)
    npm_imports = imports["npm"]
    deployment_assets = _deployment_context(root, config)
    analyzed = []
    for finding in findings:
        if finding.category == "container":
            metadata = dict(finding.metadata)
            metadata["usage"] = {
                "classification": "container_inventory",
                "reason": "The vulnerable package is present in the supplied container-image inventory; runtime execution is not inferred.",
            }
            metadata["recommendation"] = {
                "action": "rebuild_container",
                "reason": "Update the affected package or reviewed base image, rebuild without privileged Docker access from Vulcanary, and rescan the resulting image.",
            }
            metadata["exposure"] = _exposure_context(finding, metadata, deployment_assets)
            metadata["priority"] = remediation_priority(finding, metadata)
            analyzed.append(replace(finding, metadata=metadata))
            continue
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
            metadata["exposure"] = _exposure_context(finding, metadata, deployment_assets)
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
        elif ecosystem in {"PyPI", "Maven", "NuGet", "Go", "crates.io", "RubyGems"}:
            evidence = _correlated_imports(str(ecosystem), package, imports)
            if evidence:
                matched.append(package)
                paths.update(evidence)
        if matched:
            if ecosystem == "npm" and not metadata.get("direct"):
                status = "parent_import_observed"
                reason = "An introducing direct dependency is imported by application source."
            else:
                status = "direct_import_observed"
                reason = "A dependency name or namespace correlated with an import in application source; this does not prove the vulnerable code path executes."
        elif ecosystem in _REACHABILITY_ECOSYSTEMS:
            status = "not_observed"
            reason = "No static import was observed; the package may still be reachable through dynamic loading, tooling, runtime plugins, or indirect execution."
        else:
            status = "unknown"
            reason = f"Vulcanary has no reliable source-import correlation for {ecosystem or 'this ecosystem'}; reachability remains unknown."
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
        elif matched:
            usage = "dependency_import_observed"
            usage_reason = "A dependency name or namespace correlated with source import evidence, but static analysis does not prove vulnerable code execution."
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
            if usage == "tooling_path_via_runtime_parent":
                action = "evaluate_tooling_remediation"
                recommendation = "Evaluate a compatible lockfile resolution first; if the current parent remains pinned, test a parent-scoped override in isolation. Keep the advisory visible because tooling still processes repository input."
            else:
                action = "evaluate_platform_upgrade"
                recommendation = "Evaluate the compatible Expo platform set in isolation; avoid forcing an unscoped transitive override."
        elif not metadata.get("direct") and parents:
            if usage == "tooling_path_via_runtime_parent":
                action = "evaluate_tooling_remediation"
                recommendation = f"Evaluate compatible lockfile updates for {package}; if {', '.join(parents)} remains pinned, test a parent-scoped override in isolation."
            else:
                action = "evaluate_parent_upgrade"
                recommendation = f"Evaluate upgrades for {', '.join(parents)} in isolation, then rescan the resolved lockfile."
        elif metadata.get("direct"):
            action = "review_major_upgrade"
            recommendation = f"Review the breaking changes required to move {package} to {fixed}, test, and rescan."
        else:
            action = "trace_upstream"
            recommendation = "Trace the introducing package and prefer an upstream upgrade over a global transitive override."
        metadata["recommendation"] = {"action": action, "reason": recommendation}
        metadata["exposure"] = _exposure_context(finding, metadata, deployment_assets)
        metadata["priority"] = remediation_priority(finding, metadata)
        analyzed.append(replace(finding, metadata=metadata))
    return analyzed
