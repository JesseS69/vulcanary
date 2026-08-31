from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config
from .reporters import baseline_identities, findings_new_since, render_console, render_github_annotations, write_json, write_sarif
from .scanners import inline_suppression_register, ruleset_manifest, scan
from .dependencies import discover_packages, scan_dependencies
from .reachability import analyze_reachability
from .sbom import cyclonedx_document, spdx_document, write_cyclonedx, write_spdx
from .governance import suppression_findings
from .provenance import scan_provenance, write_provenance
from .adapters import AdapterError, import_report


def scan_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary", description="Scan a repository for security risks.")
    result.add_argument("path", nargs="?", default=".", help="Repository to scan")
    result.add_argument("--config", type=Path, help="Configuration JSON path")
    result.add_argument("--json", type=Path, dest="json_path", help="Write normalized JSON report")
    result.add_argument("--sarif", type=Path, help="Write SARIF 2.1 report")
    result.add_argument("--sbom", type=Path, help="Write a CycloneDX 1.5 SBOM")
    result.add_argument("--spdx", type=Path, help="Write an SPDX 2.3 JSON SBOM")
    result.add_argument("--ruleset-manifest", type=Path, help="Write the canonical built-in ruleset manifest and SHA-256 digest")
    result.add_argument("--provenance", type=Path, help="Write an unsigned in-toto scan provenance statement for generated artifacts")
    result.add_argument("--baseline-json", type=Path, help="Gate only findings absent from a prior normalized JSON report")
    result.add_argument("--github-annotations", action="store_true", help="Emit GitHub Actions workflow annotations for gated findings")
    result.add_argument("--no-fail", action="store_true", help="Always exit successfully")
    result.add_argument("--offline", action="store_true", help="Skip OSV dependency advisory queries")
    for scanner in ("semgrep", "gitleaks", "trivy", "checkov"):
        result.add_argument(f"--{scanner}-json", action="append", type=Path, default=[], help=f"Import a {scanner.title()} JSON report; repeat as needed")
    result.add_argument("--trivy-image-json", action="append", type=Path, default=[], help="Import a local Trivy container-image JSON report; repeat as needed")
    return result


def dashboard_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary dashboard", description="Launch the local Vulcanary dashboard.")
    result.add_argument("--repository", "-r", action="append", type=Path, default=[], help="Repository to scan on startup; repeat for multiple repositories")
    result.add_argument("--host", default="127.0.0.1", help="Dashboard bind address")
    result.add_argument("--port", type=int, default=8765, help="Dashboard port")
    result.add_argument("--no-open", action="store_true", help="Do not open a browser automatically")
    return result


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "dashboard":
        args = dashboard_parser().parse_args(argv[1:])
        from .dashboard import serve
        return serve(args.host, args.port, args.repository, open_browser=not args.no_open)
    args = scan_parser().parse_args(argv)
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: repository does not exist: {root}", file=sys.stderr)
        return 2
    try:
        config = Config.load(root, args.config)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"error: invalid Vulcanary configuration: {error}", file=sys.stderr)
        return 2
    findings = scan(root, config)
    try:
        imported = [finding for scanner in ("semgrep", "gitleaks", "trivy", "checkov") for report in getattr(args, f"{scanner}_json") for finding in import_report(scanner, report, root)]
        imported += [finding for report in args.trivy_image_json for finding in import_report("trivy-image", report, root)]
    except AdapterError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    imported = [finding for finding in imported if finding.rule_id not in config.ignored_rules and not config.is_suppressed(finding.fingerprint)]
    imported = list({finding.fingerprint: finding for finding in imported}.values())
    findings = findings + imported
    if not args.offline:
        dependency_findings, warning = scan_dependencies(root)
        dependency_findings = [finding for finding in dependency_findings if not config.is_suppressed(finding.fingerprint)]
        findings += dependency_findings
        if warning:
            print(f"warning: {warning}", file=sys.stderr)
    findings = analyze_reachability(root, findings, config)
    findings = sorted(findings + suppression_findings(config), key=lambda finding: (-int(finding.severity), finding.path, finding.line))
    print(render_console(findings))
    report_policy = {
        "repository_owner": config.repository_owner, "security_contact": config.security_contact,
        "remediation_sla_days": config.remediation_sla_days,
        "deadline_source": "Local dashboard first-seen history is required for absolute deadlines.",
    }
    manifest = ruleset_manifest(config)
    report_policy["ruleset"] = {"digest": manifest["digest"], "rule_count": len(manifest["rules"])}
    if args.json_path:
        write_json(findings, args.json_path, config.suppression_register() + inline_suppression_register(root, config), report_policy)
    if args.sarif:
        write_sarif(findings, args.sarif, report_policy)
    if args.sbom:
        write_cyclonedx(cyclonedx_document(root.name, discover_packages(root), [finding.to_dict() for finding in findings]), args.sbom)
    if args.spdx:
        write_spdx(spdx_document(root.name, discover_packages(root), [finding.to_dict() for finding in findings]), args.spdx)
    if args.ruleset_manifest:
        args.ruleset_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if args.provenance:
        artifacts = [path for path in (args.json_path, args.sarif, args.sbom, args.spdx, args.ruleset_manifest) if path]
        write_provenance(scan_provenance(root.name, artifacts, manifest["digest"]), args.provenance)
    policy_findings = findings
    if args.baseline_json:
        try:
            policy_findings = findings_new_since(findings, baseline_identities(args.baseline_json))
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(f"PR policy delta: {len(policy_findings)} new finding(s), {len(findings) - len(policy_findings)} pre-existing.")
    if args.github_annotations:
        annotations = render_github_annotations(policy_findings)
        if annotations:
            print(annotations)
    blocked = any(f.severity >= config.fail_on for f in policy_findings)
    return 0 if args.no_fail or not blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
