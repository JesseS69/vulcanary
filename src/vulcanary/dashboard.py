from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import threading
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2 -- requires Python 3.11+
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import Config
from .scanners import inline_suppression_register, ruleset_manifest, scan
from .dependencies import discover_packages, scan_dependencies
from .reachability import analyze_reachability
from .sbom import cyclonedx_document, inventory_snapshot, spdx_document
from .governance import suppression_findings
from .fixes import apply_changes, commit_changes, preview as preview_fixes, rollback_changes, run_verification
from .evaluator import create_expo_candidate_branch, evaluate_expo_platform, evaluate_parent_upgrades, evaluate_scoped_overrides
from .adapters import PARSERS, import_report
from .source_fixes import apply_source_fix, preview_source_fix
from .tickets import finding_ticket, ticket_markdown


REMEDIATION_RECEIPT_FIELDS = (
    "repository", "branch", "created_at", "selected_fingerprints", "changed_files",
    "rescan_passed", "remaining_selected", "finding_count", "checks_passed", "checks_skipped", "checks",
)
RESOLUTION_PROOF_FIELDS = (
    "repository", "fingerprint", "rule_id", "title", "severity", "category", "path", "line",
    "first_seen", "last_seen", "resolved_at", "resolution_commit", "resolution_branch",
    "resolution_type", "receipt_proof", "ruleset_digest", "recurrence_index", "status", "reopened_at",
)


def _git_identity(root: Path) -> tuple[str | None, str | None]:
    safe = ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root)]
    try:
        commit = subprocess.run([*safe, "rev-parse", "HEAD"], text=True, capture_output=True, timeout=10)
        branch = subprocess.run([*safe, "branch", "--show-current"], text=True, capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    return (
        commit.stdout.strip() if commit.returncode == 0 else None,
        branch.stdout.strip() if branch.returncode == 0 else None,
    )


def resolution_record_valid(record: dict) -> bool:
    try:
        canonical = json.dumps({field: record[field] for field in RESOLUTION_PROOF_FIELDS}, sort_keys=True, separators=(",", ":")).encode()
    except (KeyError, TypeError):
        return False
    return hashlib.sha256(canonical).hexdigest() == record.get("proof")


def _seal_resolution_record(record: dict) -> None:
    canonical = json.dumps(
        {field: record[field] for field in RESOLUTION_PROOF_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    record["proof"] = hashlib.sha256(canonical).hexdigest()


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
    policy: dict

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
        self.remediation_audit: list[dict] = []
        self.pending_fix: dict | None = None
        self.last_platform_evaluation: dict | None = None
        self.last_platform_repository: str | None = None
        self.verified_fixes: dict[str, dict] = {}
        self.pending_source_fix: dict | None = None
        self.external_reports: dict[str, dict[str, list[Path]]] = {}
        self.finding_first_seen: dict[str, str] = {}
        self.finding_snapshots: dict[str, dict[str, dict]] = {}
        self.resolved_findings: list[dict] = []
        self.monitor_events: list[dict] = []
        self.monitor_enabled = True
        self.monitor_interval_seconds = 300
        self.monitor_last_scan: str | None = None
        self.monitor_next_scan: str | None = None
        self.monitor_error: str | None = None
        self._monitor_wake = threading.Event()
        self._monitor_stop = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._rescan_lock = threading.Lock()
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
                remediation_audit = payload.get("remediation_audit", [])
                self.remediation_audit = list(remediation_audit)[-200:] if isinstance(remediation_audit, list) else []
                verified = payload.get("verified_fixes", {})
                self.verified_fixes = verified if isinstance(verified, dict) else {}
                first_seen = payload.get("finding_first_seen", {})
                self.finding_first_seen = first_seen if isinstance(first_seen, dict) else {}
                finding_snapshots = payload.get("finding_snapshots", {})
                self.finding_snapshots = finding_snapshots if isinstance(finding_snapshots, dict) else {}
                resolved_findings = payload.get("resolved_findings", [])
                self.resolved_findings = list(resolved_findings)[-500:] if isinstance(resolved_findings, list) else []
                monitor_events = payload.get("monitor_events", [])
                self.monitor_events = list(monitor_events)[-500:] if isinstance(monitor_events, list) else []
                monitor = payload.get("monitor", {})
                if isinstance(monitor, dict):
                    self.monitor_enabled = monitor.get("enabled", True) is True
                    interval = monitor.get("interval_seconds", 300)
                    self.monitor_interval_seconds = interval if isinstance(interval, int) and 30 <= interval <= 86_400 else 300
            except (OSError, ValueError, TypeError):
                self.history = []
                self.inventory_snapshots = {}
                self.suppression_snapshots = {}
                self.suppression_audit = []
                self.remediation_audit = []
                self.finding_first_seen = {}
                self.finding_snapshots = {}
                self.resolved_findings = []
                self.monitor_events = []

    def _persist_history(self) -> None:
        """Replace the local state file atomically so an interrupted write cannot truncate it."""
        if not self.history_path:
            return
        temporary = self.history_path.with_name(
            f".{self.history_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps({
                "history": self.history, "inventory_snapshots": self.inventory_snapshots,
                "suppression_snapshots": self.suppression_snapshots, "suppression_audit": self.suppression_audit,
                "remediation_audit": self.remediation_audit,
                "finding_first_seen": self.finding_first_seen,
                "finding_snapshots": self.finding_snapshots,
                "resolved_findings": self.resolved_findings,
                "monitor_events": self.monitor_events,
                "monitor": {"enabled": self.monitor_enabled, "interval_seconds": self.monitor_interval_seconds},
                "verified_fixes": self.verified_fixes,
            }, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.history_path)
        except OSError:
            # Scanning and remediation must still work in restricted or read-only environments.
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

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
        dependency_findings = [finding for finding in dependency_findings if not config.is_suppressed(finding.fingerprint)]
        findings = analyze_reachability(root, findings + dependency_findings + imported, config)
        findings = sorted(findings + suppression_findings(config), key=lambda f: (-int(f.severity), f.path, f.line))
        current_inventory = inventory_snapshot(discover_packages(root))
        resolution_commit, resolution_branch = _git_identity(root)
        suppression_register = config.suppression_register() + inline_suppression_register(root, config)
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
            governed_findings = []
            overdue_count = 0
            for finding in findings:
                first_seen = self.finding_first_seen.setdefault(finding.fingerprint, scanned_at)
                first_seen_at = datetime.fromisoformat(first_seen)
                sla_days = config.remediation_sla_days[finding.severity.name.lower()]
                deadline = first_seen_at + timedelta(days=sla_days)
                remaining_days = (deadline - datetime.fromisoformat(scanned_at)).total_seconds() / 86400
                status = "overdue" if remaining_days < 0 else "due_soon" if remaining_days <= 3 else "on_track"
                overdue_count += status == "overdue"
                policy = {
                    "owner": config.repository_owner, "security_contact": config.security_contact,
                    "first_seen": first_seen, "deadline": deadline.isoformat(), "sla_days": sla_days,
                    "status": status, "days_remaining": max(0, int(remaining_days)),
                }
                governed_findings.append(finding.to_dict() | {"metadata": dict(finding.metadata, policy=policy)})
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
                findings=governed_findings,
                inventory_change=inventory_change,
                suppressions=suppression_register,
                suppression_change=suppression_change,
                report_sources=report_sources,
                policy={
                    "owner": config.repository_owner, "security_contact": config.security_contact,
                    "overdue_count": overdue_count, "sla_days": config.remediation_sla_days,
                    "ruleset": {"digest": ruleset_manifest(config)["digest"], "rule_count": len(ruleset_manifest(config)["rules"])},
                    "custom_rules": {
                        "approved": sum(item["status"] == "approved" for item in config.custom_rules),
                        "draft": sum(item["status"] == "draft" for item in config.custom_rules),
                    },
                },
            )
            self.repositories[str(root)] = result
            current_fingerprints = {finding["fingerprint"] for finding in result.findings}
            previous_findings = self.finding_snapshots.get(str(root))
            current_snapshot = {
                finding["fingerprint"]: {
                    "fingerprint": finding["fingerprint"], "rule_id": finding["rule_id"], "title": finding["title"],
                    "severity": finding["severity"], "category": finding["category"], "path": finding["path"],
                    "line": finding["line"], "first_seen": self.finding_first_seen[finding["fingerprint"]],
                    "last_seen": scanned_at,
                }
                for finding in result.findings
            }
            if previous_findings is not None:
                severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                for fingerprint in sorted(current_fingerprints - set(previous_findings)):
                    finding = current_snapshot[fingerprint]
                    prior_resolution = next((
                        item for item in reversed(self.resolved_findings)
                        if item.get("repository") == result.name and item.get("fingerprint") == fingerprint
                    ), None)
                    self.monitor_events.append({
                        "repository": result.name, "fingerprint": fingerprint,
                        "event": "reopened" if prior_resolution else "new",
                        "severity": finding["severity"], "title": finding["title"], "path": finding["path"],
                        "observed_at": scanned_at, "commit": resolution_commit,
                    })
                for fingerprint in sorted(current_fingerprints & set(previous_findings)):
                    previous_severity = previous_findings[fingerprint].get("severity", "info")
                    current_severity = current_snapshot[fingerprint]["severity"]
                    if severity_rank.get(current_severity, 0) > severity_rank.get(previous_severity, 0):
                        finding = current_snapshot[fingerprint]
                        self.monitor_events.append({
                            "repository": result.name, "fingerprint": fingerprint, "event": "severity_increased",
                            "severity": current_severity, "previous_severity": previous_severity,
                            "title": finding["title"], "path": finding["path"],
                            "observed_at": scanned_at, "commit": resolution_commit,
                        })
                for fingerprint in sorted(set(previous_findings) - current_fingerprints):
                    prior = previous_findings[fingerprint]
                    receipt = next((
                        item for item in reversed(self.remediation_audit)
                        if item.get("action") == "committed" and fingerprint in item.get("selected_fingerprints", [])
                        and item.get("repository") == result.name
                        and remediation_receipt_valid(item)
                    ), None)
                    dependency_changed = prior.get("category") == "dependency" and bool(added_refs or removed_refs)
                    recurrence_index = sum(
                        item.get("repository") == result.name and item.get("fingerprint") == fingerprint
                        for item in self.resolved_findings
                    )
                    record = {
                        "repository": result.name, "fingerprint": fingerprint, "rule_id": prior["rule_id"],
                        "title": prior["title"], "severity": prior["severity"], "category": prior["category"],
                        "path": prior["path"], "line": prior["line"], "first_seen": prior["first_seen"],
                        "last_seen": prior["last_seen"], "resolved_at": scanned_at,
                        "resolution_commit": resolution_commit, "resolution_branch": resolution_branch,
                        "resolution_type": "verified_vulcanary_fix" if receipt else "dependency_update" if dependency_changed else "observed_resolved",
                        "receipt_proof": receipt.get("proof") if receipt else None,
                        "ruleset_digest": ruleset_manifest(config)["digest"], "recurrence_index": recurrence_index,
                        "status": "resolved", "reopened_at": None,
                    }
                    _seal_resolution_record(record)
                    self.resolved_findings.append(record)
            for fingerprint in current_fingerprints:
                prior_resolution = next((
                    item for item in reversed(self.resolved_findings)
                    if item.get("repository") == result.name and item.get("fingerprint") == fingerprint
                    and item.get("status") == "resolved"
                ), None)
                if prior_resolution:
                    prior_resolution["status"] = "reopened"
                    prior_resolution["reopened_at"] = scanned_at
                    _seal_resolution_record(prior_resolution)
            self.resolved_findings = self.resolved_findings[-500:]
            self.monitor_events = self.monitor_events[-500:]
            self.finding_snapshots[str(root)] = current_snapshot
            self.verified_fixes = {
                fingerprint: proposal for fingerprint, proposal in self.verified_fixes.items()
                if proposal.get("repository") != str(root) or fingerprint in current_fingerprints
            }
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
            self._persist_history()
        return result

    def snapshot(self) -> dict:
        with self._lock:
            scans = [item.to_dict() for item in self.repositories.values()]
        findings = [dict(finding, repository=repo["name"], repository_path=repo["repository"]) for repo in scans for finding in repo["findings"]]
        for finding in findings:
            verified = self.verified_fixes.get(finding["fingerprint"])
            if verified:
                finding["metadata"] = dict(
                    finding.get("metadata", {}), fix_eligible=True, verified_fix=verified,
                    fix_strategy=verified.get("strategy", "platform"),
                )
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
            "remediation_audit": [dict(item, receipt_valid=remediation_receipt_valid(item)) for item in reversed(self.remediation_audit)],
            "resolved_findings": [dict(item, proof_valid=resolution_record_valid(item)) for item in reversed(self.resolved_findings)],
            "monitor_events": list(reversed(self.monitor_events)),
            "monitor": {
                "enabled": self.monitor_enabled, "interval_seconds": self.monitor_interval_seconds,
                "last_scan": self.monitor_last_scan, "next_scan": self.monitor_next_scan,
                "scanning": self._rescan_lock.locked(), "error": self.monitor_error,
            },
            "summary": {"total": len(findings), "counts": counts, "categories": categories, "scanners": scanners, "ruleset": {"digest": ruleset_manifest()["digest"], "rule_count": len(ruleset_manifest()["rules"])}},
        }

    def register_platform_evaluation(self, repository: str, evaluation: dict) -> None:
        resolved = set(evaluation.get("resolved", []))
        verification = evaluation.get("verification", {})
        if not resolved or not verification.get("passed") or verification.get("skipped"):
            return
        candidate = {
            "strategy": "platform", "candidate_version": evaluation["candidate_version"],
            "is_migration": bool(evaluation.get("is_migration")), "resolved": sorted(resolved),
            "repository": repository,
        }
        proposals = {}
        for finding in self.snapshot()["findings"]:
            advisory = finding.get("metadata", {}).get("advisory")
            if finding["repository_path"] == repository and advisory in resolved:
                proposals[finding["fingerprint"]] = candidate
        with self._lock:
            self.verified_fixes.update(proposals)
            self._persist_history()

    def register_override_evaluation(self, repository: str, evaluation: dict) -> None:
        proposals = {}
        findings = self.snapshot()["findings"]
        for result in evaluation.get("results", []):
            if result.get("status") != "safe_candidate" or not result.get("verification", {}).get("passed"):
                continue
            for finding in findings:
                metadata = finding.get("metadata", {})
                if finding["repository_path"] == repository and metadata.get("advisory") in result.get("resolved", []):
                    proposals[finding["fingerprint"]] = {
                        "strategy": "scoped_override", "package": result["package"],
                        "candidate_version": result["candidate_version"], "parent": result["parent"],
                        "repository": repository,
                    }
        with self._lock:
            self.verified_fixes.update(proposals)
            self._persist_history()

    def rescan_all(self) -> list[RepositoryScan]:
        if not self._rescan_lock.acquire(blocking=False):
            raise ValueError("A repository scan cycle is already running")
        try:
            with self._lock:
                repositories = [Path(repository) for repository in self.repositories]
            results = [self.scan_repository(repository) for repository in repositories]
            self.monitor_last_scan = datetime.now(timezone.utc).isoformat()
            self.monitor_error = None
            return results
        finally:
            self._rescan_lock.release()

    def configure_monitor(self, enabled: bool, interval_seconds: int) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        if not isinstance(interval_seconds, int) or not 30 <= interval_seconds <= 86_400:
            raise ValueError("Monitoring interval must be between 30 and 86400 seconds")
        with self._lock:
            self.monitor_enabled = enabled
            self.monitor_interval_seconds = interval_seconds
            self.monitor_next_scan = None
            self._persist_history()
        self._monitor_wake.set()

    def start_monitor(self) -> None:
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._monitor_stop.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, name="vulcanary-monitor", daemon=True)
        self._monitor_thread.start()

    def stop_monitor(self) -> None:
        self._monitor_stop.set()
        self._monitor_wake.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)

    def _monitor_loop(self) -> None:
        while not self._monitor_stop.is_set():
            if not self.monitor_enabled:
                self.monitor_next_scan = None
                self._monitor_wake.wait()
                self._monitor_wake.clear()
                continue
            interval = self.monitor_interval_seconds
            self.monitor_next_scan = (datetime.now(timezone.utc) + timedelta(seconds=interval)).isoformat()
            if self._monitor_wake.wait(interval):
                self._monitor_wake.clear()
                continue
            if self._monitor_stop.is_set() or not self.monitor_enabled:
                continue
            try:
                self.rescan_all()
            except (OSError, ValueError, TypeError) as error:
                self.monitor_error = str(error)

    def record_remediation(self, action: str, receipt: dict) -> None:
        with self._lock:
            self.remediation_audit.append({"action": action, **receipt})
            self.remediation_audit = self.remediation_audit[-200:]
            self._persist_history()


def remediation_receipt(applied: dict, selected: list[str]) -> dict:
    verification = applied.get("verification", {})
    validation = applied.get("validation", {})
    receipt = {
        "repository": Path(applied["repository"]).name,
        "branch": applied["branch"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "selected_fingerprints": sorted(selected),
        "changed_files": sorted(applied.get("files", [])),
        "rescan_passed": validation.get("passed") is True,
        "remaining_selected": sorted(validation.get("remaining", [])),
        "finding_count": int(validation.get("finding_count", 0)),
        "checks_passed": verification.get("passed") is True,
        "checks_skipped": verification.get("skipped") is True,
        "checks": verification.get("results", []),
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    return {**receipt, "proof": hashlib.sha256(canonical).hexdigest()}


def remediation_receipt_valid(record: dict) -> bool:
    try:
        receipt = {field: record[field] for field in REMEDIATION_RECEIPT_FIELDS}
        canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        return isinstance(record.get("proof"), str) and hashlib.sha256(canonical).hexdigest() == record["proof"]
    except (KeyError, TypeError, ValueError):
        return False


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
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _host_is_local(self) -> bool:
            host = self.headers.get("Host", "")
            port = self.server.server_address[1]
            return host.lower() in {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

        def _download_json(self, payload: dict, filename: str) -> None:
            body = json.dumps(payload, indent=2).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _download_text(self, body_text: str, filename: str) -> None:
            body = body_text.encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if not self._host_is_local():
                self.send_error(HTTPStatus.BAD_REQUEST, "Dashboard Host header must be loopback")
                return
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/api/state":
                self._json(state.snapshot())
                return
            if path in {"/api/repositories/sbom", "/api/repositories/spdx"}:
                requested = parse_qs(parsed.query).get("repository", [""])[0]
                repository = str(Path(requested).resolve()) if requested else ""
                scan_result = state.repositories.get(repository)
                if not scan_result:
                    self.send_error(HTTPStatus.NOT_FOUND, "Scan the repository before exporting its SBOM")
                    return
                safe_name = "".join(character if character.isalnum() or character in {"-", "_"} else "-" for character in scan_result.name)
                if path.endswith("/spdx"):
                    document = spdx_document(scan_result.name, discover_packages(Path(repository)), scan_result.findings)
                    self._download_json(document, f"{safe_name}-vulcanary.spdx.json")
                else:
                    document = cyclonedx_document(scan_result.name, discover_packages(Path(repository)), scan_result.findings)
                    self._download_json(document, f"{safe_name}-vulcanary.cdx.json")
                return
            if path == "/api/remediation/receipt.json":
                proof = parse_qs(parsed.query).get("proof", [""])[0]
                if not re.fullmatch(r"[0-9a-f]{64}", proof):
                    self.send_error(HTTPStatus.BAD_REQUEST, "A valid remediation proof is required")
                    return
                record = next((item for item in reversed(state.remediation_audit) if item.get("proof") == proof), None)
                if not record:
                    self.send_error(HTTPStatus.NOT_FOUND, "Remediation receipt not found")
                    return
                self._download_json({"version": 1, "receipt_valid": remediation_receipt_valid(record), "receipt": record}, f"vulcanary-remediation-{proof[:12]}.json")
                return
            if path == "/api/resolutions/record.json":
                proof = parse_qs(parsed.query).get("proof", [""])[0]
                if not re.fullmatch(r"[0-9a-f]{64}", proof):
                    self.send_error(HTTPStatus.BAD_REQUEST, "A valid resolution proof is required")
                    return
                record = next((item for item in reversed(state.resolved_findings) if item.get("proof") == proof), None)
                if not record:
                    self.send_error(HTTPStatus.NOT_FOUND, "Resolution record not found")
                    return
                self._download_json({"version": 1, "proof_valid": resolution_record_valid(record), "resolution": record}, f"vulcanary-resolution-{proof[:12]}.json")
                return
            if path == "/api/ruleset.json":
                self._download_json(ruleset_manifest(), "vulcanary-ruleset.json")
                return
            if path in {"/api/ticket.json", "/api/ticket.md"}:
                fingerprint = parse_qs(parsed.query).get("fingerprint", [""])[0]
                if not re.fullmatch(r"[0-9a-f]{20}", fingerprint):
                    self.send_error(HTTPStatus.BAD_REQUEST, "A valid finding fingerprint is required")
                    return
                finding = next((item for item in state.snapshot()["findings"] if item["fingerprint"] == fingerprint), None)
                if not finding:
                    self.send_error(HTTPStatus.NOT_FOUND, "Finding not found")
                    return
                ticket = finding_ticket(finding)
                safe_name = f"vulcanary-{finding['rule_id'].lower()}-{fingerprint[:8]}"
                if path.endswith(".md"):
                    self._download_text(ticket_markdown(ticket), f"{safe_name}.md")
                else:
                    self._download_json(ticket, f"{safe_name}.json")
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
                "/monitor.css": ("monitor.css", "text/css"),
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
            if not self._host_is_local():
                self.send_error(HTTPStatus.BAD_REQUEST, "Dashboard Host header must be loopback")
                return
            route = urlparse(self.path).path
            if route not in {"/api/scan", "/api/rescan", "/api/monitor", "/api/fixes/preview", "/api/fixes/apply", "/api/fixes/commit", "/api/source/preview", "/api/source/apply", "/api/parents/evaluate", "/api/overrides/evaluate", "/api/platform/evaluate", "/api/platform/create-branch"}:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                self._json({"error": "POST requests require application/json"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                return
            origin = self.headers.get("Origin")
            expected_origin = f"http://{self.headers.get('Host', '')}"
            if origin and origin != expected_origin:
                self._json({"error": "Cross-origin dashboard actions are forbidden"}, HTTPStatus.FORBIDDEN)
                return
            fetch_site = self.headers.get("Sec-Fetch-Site")
            if fetch_site and fetch_site not in {"same-origin", "none"}:
                self._json({"error": "Cross-site dashboard actions are forbidden"}, HTTPStatus.FORBIDDEN)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 16_384:
                    raise ValueError("Request is too large")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Request body must be a JSON object")
                if route == "/api/rescan":
                    rescanned = state.rescan_all()
                    self._json({"scans": [result.to_dict() for result in rescanned], "state": state.snapshot()})
                elif route == "/api/monitor":
                    state.configure_monitor(payload.get("enabled"), payload.get("interval_seconds"))
                    self._json({"state": state.snapshot()})
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
                elif route == "/api/source/preview":
                    fingerprint = payload.get("fingerprint")
                    matches = [finding for finding in state.snapshot()["findings"] if finding["fingerprint"] == fingerprint]
                    if len(matches) != 1:
                        raise ValueError("Select one current source finding")
                    proposal = preview_source_fix(matches[0])
                    state.pending_source_fix = proposal
                    self._json({"proposal": {key: proposal[key] for key in ("fingerprint", "repository", "file", "files", "line", "rule_id", "recipe", "diff")}})
                elif route == "/api/source/apply":
                    proposal = state.pending_source_fix
                    if not proposal or proposal["fingerprint"] != payload.get("fingerprint"):
                        raise ValueError("Preview the current source fix before applying it")
                    applied = apply_source_fix(proposal)
                    result = state.scan_repository(Path(applied["repository"]))
                    remaining = [finding for finding in result.findings if finding["rule_id"] == proposal["rule_id"] and finding["path"] == proposal["file"]]
                    config = Config.load(Path(applied["repository"]))
                    applied["validation"] = {"passed": not remaining, "remaining": [finding["fingerprint"] for finding in remaining], "finding_count": len(result.findings)}
                    applied["verification"] = run_verification(
                        applied["repository"], config.verify_commands, config.verify_timeout_seconds,
                    ) if not remaining else {"passed": False, "skipped": True, "results": []}
                    if remaining or not applied["verification"]["passed"]:
                        applied["rollback"] = rollback_changes(applied["repository"], applied["branch"], applied["original_branch"])
                        restored = state.scan_repository(Path(applied["repository"]))
                        applied["validation"]["finding_count"] = len(restored.findings)
                        applied["validation"]["passed"] = False
                        applied["diagnostic"] = "The source draft failed validation; the original branch and clean working tree were restored."
                        applied["receipt"] = remediation_receipt(applied, [proposal["fingerprint"]])
                        state.record_remediation("rolled_back", applied["receipt"])
                        state.pending_fix = None
                    else:
                        applied["receipt"] = remediation_receipt(applied, [proposal["fingerprint"]])
                        state.record_remediation("verified", applied["receipt"])
                        state.pending_fix = applied
                    state.pending_source_fix = None
                    self._json({"applied": applied})
                elif route == "/api/fixes/apply":
                    plan = preview_fixes(state.snapshot()["findings"], payload.get("fingerprints", []))
                    strategies = {item.get("strategy") for item in plan["changes"]}
                    if "platform" in strategies:
                        if strategies != {"platform"}:
                            raise ValueError("Apply verified platform fixes separately from direct dependency upgrades")
                        versions = {item["to"] for item in plan["changes"]}
                        migrations = {item.get("is_migration", False) for item in plan["changes"]}
                        repositories = {item["repository_path"] for item in plan["changes"]}
                        if len(versions) != 1 or len(migrations) != 1 or len(repositories) != 1:
                            raise ValueError("Selected platform fixes do not share one verified candidate")
                        selected_repository = repositories.pop()
                        applied = create_expo_candidate_branch(selected_repository, versions.pop(), migrations.pop())
                        applied["repository"] = selected_repository
                    else:
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
                        selected = [item for item in payload.get("fingerprints", []) if isinstance(item, str)]
                        applied["receipt"] = remediation_receipt(applied, selected)
                        state.record_remediation("rolled_back", applied["receipt"])
                        state.pending_fix = None
                    else:
                        selected = [item for item in payload.get("fingerprints", []) if isinstance(item, str)]
                        applied["receipt"] = remediation_receipt(applied, selected)
                        state.record_remediation("verified", applied["receipt"])
                        state.pending_fix = applied
                    self._json({"applied": applied})
                elif route == "/api/parents/evaluate":
                    repository = str(Path(payload["repository"]).resolve())
                    if repository not in state.repositories:
                        raise ValueError("Scan the repository before evaluating parent upgrades")
                    requested = payload.get("packages")
                    packages = set(requested) if isinstance(requested, list) and all(isinstance(item, str) for item in requested) else None
                    self._json({"evaluation": evaluate_parent_upgrades(state.snapshot()["findings"], repository, packages=packages)})
                elif route == "/api/overrides/evaluate":
                    repository = str(Path(payload["repository"]).resolve())
                    if repository not in state.repositories:
                        raise ValueError("Scan the repository before evaluating scoped overrides")
                    evaluation = evaluate_scoped_overrides(state.snapshot()["findings"], repository)
                    state.register_override_evaluation(repository, evaluation)
                    self._json({"evaluation": evaluation, "state": state.snapshot()})
                elif route == "/api/platform/evaluate":
                    repository = str(Path(payload["repository"]).resolve())
                    if repository not in state.repositories:
                        raise ValueError("Scan the repository before evaluating its platform set")
                    evaluation = evaluate_expo_platform(state.snapshot()["findings"], repository, test_migration=payload.get("migration") is True)
                    state.last_platform_evaluation = dict(evaluation, repository=Path(repository).name)
                    state.last_platform_repository = repository
                    state.register_platform_evaluation(repository, evaluation)
                    self._json({"evaluation": evaluation})
                elif route == "/api/platform/create-branch":
                    report = state.last_platform_evaluation
                    repository = state.last_platform_repository
                    if not report or not repository or not report.get("verification", {}).get("passed"):
                        raise ValueError("Evaluate and verify an Expo candidate before creating its branch")
                    created = create_expo_candidate_branch(repository, report["candidate_version"], bool(report.get("is_migration")))
                    self._json({"created": created})
                else:
                    if not state.pending_fix:
                        raise ValueError("No applied fix batch is waiting to be committed")
                    receipt = state.pending_fix.get("receipt")
                    if not receipt or not receipt.get("rescan_passed") or not receipt.get("checks_passed"):
                        raise ValueError("The fix batch has no passing remediation receipt")
                    committed = commit_changes(state.pending_fix["repository"], state.pending_fix["branch"])
                    committed["receipt"] = receipt
                    state.record_remediation("committed", {**receipt, "commit": committed["commit"]})
                    state.pending_fix = None
                    self._json({"committed": committed})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)

    return Handler


def serve(host: str, port: int, repositories: list[Path], open_browser: bool = True, monitor_interval: int | None = None) -> int:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The dashboard is local-only; bind to a loopback address")
    state = DashboardState(Path.home() / ".vulcanary" / "dashboard-history.json")
    for repository in repositories:
        state.scan_repository(repository)
    if monitor_interval is not None:
        state.configure_monitor(monitor_interval > 0, monitor_interval if monitor_interval > 0 else state.monitor_interval_seconds)
    state.start_monitor()
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
        state.stop_monitor()
        server.server_close()
    return 0
