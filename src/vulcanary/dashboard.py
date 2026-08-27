from __future__ import annotations

import json
import threading
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2 -- requires Python 3.11+
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import Config
from .scanners import scan
from .dependencies import discover_packages, scan_dependencies
from .reachability import analyze_reachability
from .sbom import cyclonedx_document, inventory_snapshot
from .governance import suppression_findings
from .fixes import apply_changes, commit_changes, preview as preview_fixes, rollback_changes, run_verification
from .evaluator import create_expo_migration_branch, evaluate_expo_platform, evaluate_parent_upgrades
from .adapters import PARSERS, import_report


@dataclass
class RepositoryScan:
    repository: str
    name: str
    scanned_at: str
    duration_ms: int
    findings: list[dict]
    inventory_change: dict
    suppressions: list[dict]
    suppression_change: dict
    report_sources: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class DashboardState:
    def __init__(self, history_path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self.repositories: dict[str, RepositoryScan] = {}
        self.history_path = history_path
        self.history: list[dict] = []
        self.inventory_snapshots: dict[str, dict[str, dict]] = {}
        self.suppression_snapshots: dict[str, dict[str, dict]] = {}
        self.suppression_audit: list[dict] = []
        self.pending_fix: dict | None = None
        self.last_platform_evaluation: dict | None = None
        self.last_platform_repository: str | None = None
        self.external_reports: dict[str, dict[str, list[Path]]] = {}
        if history_path and history_path.exists():
            try:
                payload = json.loads(history_path.read_text(encoding="utf-8"))
                self.history = list(payload.get("history", []))[-100:]
                snapshots = payload.get("inventory_snapshots", {})
                self.inventory_snapshots = snapshots if isinstance(snapshots, dict) else {}
                suppression_snapshots = payload.get("suppression_snapshots", {})
                self.suppression_snapshots = suppression_snapshots if isinstance(suppression_snapshots, dict) else {}
                audit = payload.get("suppression_audit", [])
                self.suppression_audit = list(audit)[-500:] if isinstance(audit, list) else []
            except (OSError, ValueError, TypeError):
                self.history = []
                self.inventory_snapshots = {}
                self.suppression_snapshots = {}
                self.suppression_audit = []

    def scan_repository(self, path: Path, external_reports: dict[str, list[Path]] | None = None) -> RepositoryScan:
        import time
        root = path.resolve()
        if not root.is_dir():
            raise ValueError(f"Repository does not exist: {root}")
        started = time.perf_counter()
        config = Config.load(root)
        findings = scan(root, config)
        repository_key = str(root)
        reports = external_reports if external_reports is not None else self.external_reports.get(repository_key, {})
        imported = []
        report_sources = []
        for scanner, paths in reports.items():
            if scanner not in PARSERS:
                raise ValueError(f"Unsupported external scanner: {scanner}")
            for report in paths:
                resolved = report.resolve()
                imported.extend(import_report(scanner, resolved, root))
                report_sources.append({"scanner": scanner, "path": str(resolved)})
        imported = [finding for finding in imported if finding.rule_id not in config.ignored_rules and not config.is_suppressed(finding.fingerprint)]
        imported = list({finding.fingerprint: finding for finding in imported}.values())
        if external_reports is not None:
            self.external_reports[repository_key] = external_reports
        dependency_findings, dependency_warning = scan_dependencies(root)
        dependency_findings = analyze_reachability(root, dependency_findings, config)
        dependency_findings = [finding for finding in dependency_findings if not config.is_suppressed(finding.fingerprint)]
        findings = sorted(findings + dependency_findings + imported + suppression_findings(config), key=lambda f: (-int(f.severity), f.path, f.line))
        current_inventory = inventory_snapshot(discover_packages(root))
        suppression_register = config.suppression_register()
        current_suppressions = {item["fingerprint"]: item for item in suppression_register}
        with self._lock:
            previous_inventory = self.inventory_snapshots.get(str(root))
            added_refs = sorted(set(current_inventory) - set(previous_inventory or {})) if previous_inventory is not None else []
            removed_refs = sorted(set(previous_inventory or {}) - set(current_inventory)) if previous_inventory is not None else []
            inventory_change = {
                "baseline": previous_inventory is None,
                "current_count": len(current_inventory),
                "previous_count": len(previous_inventory) if previous_inventory is not None else None,
                "added": [dict(current_inventory[reference], ref=reference) for reference in added_refs],
                "removed": [dict(previous_inventory[reference], ref=reference) for reference in removed_refs],
            }
            previous_suppressions = self.suppression_snapshots.get(str(root))
            added_suppressions = sorted(set(current_suppressions) - set(previous_suppressions or {})) if previous_suppressions is not None else []
            removed_suppressions = sorted(set(previous_suppressions or {}) - set(current_suppressions)) if previous_suppressions is not None else []
            changed_suppressions = sorted(
                fingerprint for fingerprint in set(current_suppressions) & set(previous_suppressions or {})
                if current_suppressions[fingerprint] != previous_suppressions[fingerprint]
            ) if previous_suppressions is not None else []
            suppression_change = {
                "baseline": previous_suppressions is None,
                "added": [current_suppressions[fingerprint] for fingerprint in added_suppressions],
                "changed": [current_suppressions[fingerprint] for fingerprint in changed_suppressions],
                "removed": [previous_suppressions[fingerprint] for fingerprint in removed_suppressions],
            }
            scanned_at = datetime.now(timezone.utc).isoformat()
            for action, records in (("added", suppression_change["added"]), ("changed", suppression_change["changed"]), ("removed", suppression_change["removed"])):
                for record in records:
                    self.suppression_audit.append({
                        "repository": root.name, "scanned_at": scanned_at, "action": action,
                        "fingerprint": record["fingerprint"], "owner": record["owner"],
                        "reason": record["reason"], "expires": record["expires"],
                    })
            self.suppression_audit = self.suppression_audit[-500:]
            result = RepositoryScan(
                repository=str(root),
                name=root.name,
                scanned_at=scanned_at,
                duration_ms=round((time.perf_counter() - started) * 1000),
                findings=[finding.to_dict() for finding in findings],
                inventory_change=inventory_change,
                suppressions=suppression_register,
                suppression_change=suppression_change,
                report_sources=report_sources,
            )
            self.repositories[str(root)] = result
            self.inventory_snapshots[str(root)] = current_inventory
            self.suppression_snapshots[str(root)] = current_suppressions
            self.history.append({
                "repository": result.repository,
                "name": result.name,
                "scanned_at": result.scanned_at,
                "duration_ms": result.duration_ms,
                "finding_count": len(result.findings),
                "suppression_count": len(result.suppressions),
                "suppression_change_count": sum(len(suppression_change[key]) for key in ("added", "changed", "removed")),
            })
            self.history = self.history[-100:]
            if self.history_path:
                try:
                    self.history_path.parent.mkdir(parents=True, exist_ok=True)
                    self.history_path.write_text(json.dumps({
                        "history": self.history, "inventory_snapshots": self.inventory_snapshots,
                        "suppression_snapshots": self.suppression_snapshots, "suppression_audit": self.suppression_audit,
                    }, indent=2) + "\n", encoding="utf-8")
                except OSError:
                    # Scanning must still work in restricted or read-only environments.
                    pass
        return result

    def snapshot(self) -> dict:
        with self._lock:
            scans = [item.to_dict() for item in self.repositories.values()]
        findings = [dict(finding, repository=repo["name"], repository_path=repo["repository"]) for repo in scans for finding in repo["findings"]]
        counts = {severity: sum(item["severity"] == severity for item in findings) for severity in ("critical", "high", "medium", "low", "info")}
        categories: dict[str, int] = {}
        scanners: dict[str, int] = {}
        for item in findings:
            categories[item["category"]] = categories.get(item["category"], 0) + 1
            scanners[item["scanner"]] = scanners.get(item["scanner"], 0) + 1
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repositories": scans,
            "findings": findings,
            "history": list(reversed(self.history)),
            "suppression_audit": list(reversed(self.suppression_audit)),
            "summary": {"total": len(findings), "counts": counts, "categories": categories, "scanners": scanners},
        }

    def rescan_all(self) -> list[RepositoryScan]:
        with self._lock:
            repositories = [Path(repository) for repository in self.repositories]
        return [self.scan_repository(repository) for repository in repositories]


def _assets() -> Path:
    return Path(str(files("vulcanary").joinpath("dashboard_assets")))


def make_handler(state: DashboardState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def _json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _download_json(self, payload: dict, filename: str) -> None:
            body = json.dumps(payload, indent=2).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/api/state":
                self._json(state.snapshot())
                return
            if path == "/api/repositories/sbom":
                requested = parse_qs(parsed.query).get("repository", [""])[0]
                repository = str(Path(requested).resolve()) if requested else ""
                scan_result = state.repositories.get(repository)
                if not scan_result:
                    self.send_error(HTTPStatus.NOT_FOUND, "Scan the repository before exporting its SBOM")
                    return
                document = cyclonedx_document(scan_result.name, discover_packages(Path(repository)), scan_result.findings)
                safe_name = "".join(character if character.isalnum() or character in {"-", "_"} else "-" for character in scan_result.name)
                self._download_json(document, f"{safe_name}-vulcanary.cdx.json")
                return
            if path in {"/api/platform/report.json", "/api/platform/report.sarif"}:
                if not state.last_platform_evaluation:
                    self.send_error(HTTPStatus.NOT_FOUND, "No platform evaluation is available")
                    return
                if path.endswith(".json"):
                    self._download_json(state.last_platform_evaluation, "vulcanary-platform-report.json")
                else:
                    report = state.last_platform_evaluation
                    diagnostics = report.get("verification", {}).get("diagnostics", [])
                    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Vulcanary Platform Evaluator", "rules": [{"id": item["code"]} for item in {entry["code"]: entry for entry in diagnostics}.values()]}}, "results": [{"ruleId": item["code"], "message": {"text": "TypeScript migration compatibility error"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": item["path"]}, "region": {"startLine": item["line"], "startColumn": item["column"]}}}]} for item in diagnostics]}]}
                    self._download_json(sarif, "vulcanary-platform-report.sarif")
                return
            assets = {
                "/": ("index.html", "text/html"),
                "/app.js": ("app.js", "text/javascript"),
                "/styles.css": ("styles.css", "text/css"),
                "/brand.css": ("brand.css", "text/css"),
                "/forge.css": ("forge.css", "text/css"),
                "/fixes.css": ("fixes.css", "text/css"),
                "/vulcanary-logo.png": ("vulcanary-logo.png", "image/png"),
                "/vulcanary-favicon.png": ("vulcanary-favicon.png", "image/png"),
            }
            if path not in assets:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            filename, content_type = assets[path]
            body = (_assets() / filename).read_bytes()
            self.send_response(HTTPStatus.OK)
            rendered_type = f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type
            self.send_header("Content-Type", rendered_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            route = urlparse(self.path).path
            if route not in {"/api/scan", "/api/rescan", "/api/fixes/preview", "/api/fixes/apply", "/api/fixes/commit", "/api/parents/evaluate", "/api/platform/evaluate", "/api/platform/create-branch"}:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 16_384:
                    raise ValueError("Request is too large")
                payload = json.loads(self.rfile.read(length))
                if route == "/api/rescan":
                    rescanned = state.rescan_all()
                    self._json({"scans": [result.to_dict() for result in rescanned], "state": state.snapshot()})
                elif route == "/api/scan":
                    repository = Path(payload["repository"])
                    submitted = payload.get("reports", {})
                    if not isinstance(submitted, dict):
                        raise ValueError("reports must be an object")
                    reports = {}
                    for scanner, value in submitted.items():
                        if scanner not in PARSERS:
                            raise ValueError(f"Unsupported external scanner: {scanner}")
                        values = value if isinstance(value, list) else [value]
                        if any(not isinstance(item, str) or not item.strip() for item in values):
                            raise ValueError(f"{scanner} report paths must be non-empty strings")
                        reports[scanner] = [Path(item) for item in values]
                    result = state.scan_repository(repository, reports if submitted else None)
                    self._json({"scan": result.to_dict(), "state": state.snapshot()})
                elif route == "/api/fixes/preview":
                    self._json({"plan": preview_fixes(state.snapshot()["findings"], payload.get("fingerprints", []))})
                elif route == "/api/fixes/apply":
                    plan = preview_fixes(state.snapshot()["findings"], payload.get("fingerprints", []))
                    applied = apply_changes(plan)
                    result = state.scan_repository(Path(applied["repository"]))
                    expected = {f"SCA-{advisory}" for item in plan["changes"] for advisory in item.get("advisories", [item["advisory"]])}
                    remaining = sorted(expected & {item["rule_id"] for item in result.findings})
                    applied["validation"] = {"passed": not remaining, "remaining": remaining, "finding_count": len(result.findings)}
                    config = Config.load(Path(applied["repository"]))
                    applied["verification"] = run_verification(
                        applied["repository"], config.verify_commands, config.verify_timeout_seconds,
                    ) if not remaining else {"passed": False, "skipped": True, "results": []}
                    if remaining or not applied["verification"]["passed"]:
                        applied["rollback"] = rollback_changes(applied["repository"], applied["branch"], applied["original_branch"])
                        restored = state.scan_repository(Path(applied["repository"]))
                        applied["validation"]["finding_count"] = len(restored.findings)
                        if remaining:
                            applied["diagnostic"] = f"Validation found {len(remaining)} selected advisories still present; npm files and branch were restored."
                        else:
                            applied["validation"]["passed"] = False
                            applied["diagnostic"] = f"Project verification failed at {applied['verification']['failed_command']}; npm files and branch were restored."
                        state.pending_fix = None
                    else:
                        state.pending_fix = applied
                    self._json({"applied": applied})
                elif route == "/api/parents/evaluate":
                    repository = str(Path(payload["repository"]).resolve())
                    if repository not in state.repositories:
                        raise ValueError("Scan the repository before evaluating parent upgrades")
                    requested = payload.get("packages")
                    packages = set(requested) if isinstance(requested, list) and all(isinstance(item, str) for item in requested) else None
                    self._json({"evaluation": evaluate_parent_upgrades(state.snapshot()["findings"], repository, packages=packages)})
                elif route == "/api/platform/evaluate":
                    repository = str(Path(payload["repository"]).resolve())
                    if repository not in state.repositories:
                        raise ValueError("Scan the repository before evaluating its platform set")
                    evaluation = evaluate_expo_platform(state.snapshot()["findings"], repository, test_migration=payload.get("migration") is True)
                    state.last_platform_evaluation = dict(evaluation, repository=Path(repository).name)
                    state.last_platform_repository = repository
                    self._json({"evaluation": evaluation})
                elif route == "/api/platform/create-branch":
                    report = state.last_platform_evaluation
                    repository = state.last_platform_repository
                    if not report or not report.get("is_migration") or not repository:
                        raise ValueError("Evaluate an explicit SDK migration before creating its branch")
                    created = create_expo_migration_branch(repository, report["candidate_version"])
                    self._json({"created": created})
                else:
                    if not state.pending_fix:
                        raise ValueError("No applied fix batch is waiting to be committed")
                    committed = commit_changes(state.pending_fix["repository"], state.pending_fix["branch"])
                    state.pending_fix = None
                    self._json({"committed": committed})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)

    return Handler


def serve(host: str, port: int, repositories: list[Path], open_browser: bool = True) -> int:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The dashboard is local-only; bind to a loopback address")
    state = DashboardState(Path.home() / ".vulcanary" / "dashboard-history.json")
    for repository in repositories:
        state.scan_repository(repository)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    url = f"http://{host}:{server.server_port}"
    print(f"Vulcanary dashboard: {url}")
    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
