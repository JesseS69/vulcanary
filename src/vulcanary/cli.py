from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

from .config import Config
from .reporters import baseline_identities, findings_new_since, render_console, render_github_annotations, render_markdown_summary, write_json, write_sarif
from .scanners import inline_suppression_register, is_excluded, ruleset_manifest, scan
from .dependencies import discover_dependency_state, scan_dependencies
from .reachability import analyze_reachability
from .sbom import cyclonedx_document, spdx_document, write_cyclonedx, write_spdx
from .governance import suppression_findings
from .provenance import scan_provenance, write_provenance
from .vex import openvex_document, write_openvex
from .adapters import AdapterError, import_report


def scan_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="vulcanary", description="Scan a repository for security risks.",
        epilog="Commands: setup | start | status | stop | dashboard | config-export | config-import | dependency-review | web-audit | dataflow-prototype | update-check",
    )
    result.add_argument("path", nargs="?", default=".", help="Repository to scan")
    result.add_argument("--config", type=Path, help="Configuration JSON path")
    result.add_argument("--json", type=Path, dest="json_path", help="Write normalized JSON report")
    result.add_argument("--sarif", type=Path, help="Write SARIF 2.1 report")
    result.add_argument("--sbom", type=Path, help="Write a CycloneDX 1.5 SBOM")
    result.add_argument("--spdx", type=Path, help="Write an SPDX 2.3 JSON SBOM")
    result.add_argument("--openvex", type=Path, help="Write an OpenVEX document for observed dependency vulnerabilities")
    result.add_argument("--ruleset-manifest", type=Path, help="Write the canonical built-in ruleset manifest and SHA-256 digest")
    result.add_argument("--provenance", type=Path, help="Write an unsigned in-toto scan provenance statement for generated artifacts")
    result.add_argument("--baseline-json", type=Path, help="Gate only findings absent from a prior normalized JSON report")
    result.add_argument("--github-annotations", action="store_true", help="Emit GitHub Actions workflow annotations for gated findings")
    result.add_argument("--github-summary", action="store_true", help="Append a source-free Markdown summary to GITHUB_STEP_SUMMARY")
    result.add_argument("--no-fail", action="store_true", help="Always exit successfully")
    result.add_argument("--offline", action="store_true", help="Skip OSV dependency advisory queries")
    for scanner in ("semgrep", "gitleaks", "trivy", "checkov", "zap", "prowler", "sarif"):
        result.add_argument(f"--{scanner}-json", action="append", type=Path, default=[], help=f"Import a {scanner.title()} JSON report; repeat as needed")
    result.add_argument("--trivy-image-json", action="append", type=Path, default=[], help="Import a local Trivy container-image JSON report; repeat as needed")
    return result


def dashboard_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary dashboard", description="Launch the local Vulcanary dashboard.")
    result.add_argument("--repository", "-r", action="append", type=Path, default=[], help="Repository to scan on startup; repeat for multiple repositories")
    result.add_argument("--host", default="127.0.0.1", help="Dashboard bind address")
    result.add_argument("--port", type=int, default=8765, help="Dashboard port")
    result.add_argument("--no-open", action="store_true", help="Do not open a browser automatically")
    result.add_argument("--monitor-interval", type=int, help="Automatic rescan interval in seconds (30-86400); use 0 to start paused")
    result.add_argument("--history-secrets", action="store_true", help="Opt in to out-of-band Git-history secret scanning")
    result.add_argument("--gitleaks-executable", type=Path, help="Explicit absolute path to the trusted Gitleaks executable")
    return result


def setup_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary setup", description="Configure repositories for the local Vulcanary service.")
    result.add_argument("--repository", "-r", action="append", type=Path, default=[], help="Repository to watch; repeat for multiple repositories")
    result.add_argument("--monitor-interval", type=int, default=300, help="Automatic scan interval in seconds, or 0 to start paused")
    result.add_argument("--port", type=int, default=8765, help="Loopback dashboard port")
    result.add_argument("--history-secrets", action="store_true", help="Opt in to out-of-band Git-history secret scanning")
    result.add_argument("--gitleaks-executable", type=Path, help="Explicit absolute path to the trusted Gitleaks executable")
    return result


def service_parser(command: str) -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog=f"vulcanary {command}", description=f"{command.title()} the local Vulcanary service.")
    if command == "start":
        result.add_argument("--no-open", action="store_true", help="Do not open the dashboard after starting")
    return result


def config_transfer_parser(command: str) -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog=f"vulcanary {command}", description=f"{command.replace('-', ' ').title()} without secrets or source content.")
    result.add_argument("path", type=Path)
    return result


def dependency_review_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary dependency-review", description="Review newly introduced locked dependencies without installing or executing them.")
    result.add_argument("path", nargs="?", default=".", help="Current repository checkout")
    result.add_argument("--base", required=True, type=Path, help="Trusted base checkout to compare")
    result.add_argument("--json", type=Path, dest="json_path", help="Write a normalized JSON report")
    result.add_argument("--github-annotations", action="store_true")
    result.add_argument("--no-fail", action="store_true")
    return result


def web_audit_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary web-audit", description="Run a non-exploitative HTTP security-header and cookie audit against an authorized target.")
    result.add_argument("url")
    result.add_argument("--authorize-target", required=True, help="Exact hostname you own or are authorized to test")
    result.add_argument("--allow-private-target", action="store_true", help="Explicitly permit an authorized private or loopback target")
    result.add_argument("--json", type=Path, dest="json_path")
    result.add_argument("--no-fail", action="store_true")
    return result


def dataflow_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary dataflow-prototype", description="Run the experimental, non-gating Python dataflow prototype.")
    result.add_argument("path", nargs="?", default=".", type=Path)
    result.add_argument("--max-depth", type=int, default=3, choices=range(1, 11))
    result.add_argument("--json", type=Path, dest="json_path")
    result.add_argument("--benchmark-expected", type=Path, help="Score CWE-94 cases against BenchmarkPython expectedresults CSV")
    return result


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "dataflow-prototype":
        args = dataflow_parser().parse_args(argv[1:])
        from .dataflow import analyze_python_dataflow, benchmark_python_score, write_dataflow_report
        if not args.path.is_dir():
            print(f"error: repository does not exist: {args.path.resolve()}", file=sys.stderr)
            return 2
        try:
            report = analyze_python_dataflow(args.path, args.max_depth)
            if args.benchmark_expected:
                report["benchmark"] = benchmark_python_score(report, args.benchmark_expected)
            if args.json_path:
                write_dataflow_report(report, args.json_path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f"error: dataflow prototype failed: {error}", file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2))
        return 0
    if argv and argv[0] in {"config-export", "config-import"}:
        command = argv[0]
        args = config_transfer_parser(command).parse_args(argv[1:])
        try:
            from .local_app import export_app_config, import_app_config
            if command == "config-export":
                path = export_app_config(args.path)
                print(f"Configuration backup written to {path}. Control tokens, history, findings, and source are excluded.")
            else:
                configured = import_app_config(args.path)
                print(f"Restored {len(configured['repositories'])} repositories. Restart Vulcanary to apply the configuration.")
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        return 0
    if argv and argv[0] == "web-audit":
        args = web_audit_parser().parse_args(argv[1:])
        try:
            from .webaudit import audit_web_target
            findings = audit_web_target(args.url, args.authorize_target, allow_private=args.allow_private_target)
        except (OSError, ValueError) as error:
            print(f"error: web audit failed: {error}", file=sys.stderr)
            return 2
        print(render_console(findings))
        if args.json_path:
            write_json(findings, args.json_path, policy={"mode": "passive-web-audit", "authorized_host": args.authorize_target})
        return 0 if args.no_fail or not any(item.severity >= Config().fail_on for item in findings) else 1
    if argv and argv[0] == "dependency-review":
        args = dependency_review_parser().parse_args(argv[1:])
        root, base = Path(args.path).resolve(), args.base.resolve()
        if not root.is_dir() or not base.is_dir():
            dependency_review_parser().error("path and --base must be existing directories")
        try:
            from .admission import review_dependency_changes
            findings, added = review_dependency_changes(root, base)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            print(f"error: invalid dependency admission policy: {error}", file=sys.stderr)
            return 2
        print(f"Dependency delta: {len(added)} added locked package(s).")
        print(render_console(findings))
        if args.json_path:
            write_json(findings, args.json_path, policy={"mode": "dependency-admission", "added_packages": len(added)})
        if args.github_annotations:
            annotations = render_github_annotations(findings)
            if annotations:
                print(annotations)
        return 0 if args.no_fail or not findings else 1
    if argv and argv[0] == "setup":
        args = setup_parser().parse_args(argv[1:])
        from .local_app import configure_app, config_path
        repositories = list(args.repository)
        interactive = not repositories
        if interactive:
            print("Enter repositories to watch. Submit a blank line when finished.")
            while True:
                entered = input("Repository path: ").strip()
                if not entered:
                    break
                repositories.append(Path(entered))
        if not repositories:
            setup_parser().error("configure at least one repository")
        if interactive:
            entered_interval = input(f"Automatic scan interval in seconds [{args.monitor_interval}]: ").strip()
            if entered_interval:
                try:
                    args.monitor_interval = int(entered_interval)
                except ValueError:
                    setup_parser().error("monitoring interval must be an integer")
        try:
            configured = configure_app(repositories, args.monitor_interval, args.port, args.history_secrets, args.gitleaks_executable)
        except ValueError as error:
            setup_parser().error(str(error))
        print(f"Configured {len(configured['repositories'])} repositories in {config_path()}")
        print("Run `vulcanary start` to launch continuous monitoring.")
        return 0
    if argv and argv[0] in {"start", "stop", "status"}:
        command = argv[0]
        args = service_parser(command).parse_args(argv[1:])
        from .local_app import load_app_config, service_status, start_service, stop_service
        try:
            config = load_app_config()
            if command == "start":
                status = start_service(config)
                print(f"Vulcanary {'started' if status.get('started') else 'is already running'} at {status['url']}")
                authorized_url = f"{status['url']}/?token={config['control_token']}"
                if not args.no_open:
                    webbrowser.open(authorized_url)
                else:
                    print("Open the dashboard with its local control token:")
                    print(f"  {authorized_url}")
            elif command == "stop":
                status = stop_service(config)
                print("Vulcanary stopped." if status["stopped"] else "Vulcanary is not running." if not status["running"] else "Vulcanary did not stop.")
                return 1 if status["running"] else 0
            else:
                status = service_status(config)
                if status["running"]:
                    monitor = status.get("monitor", {})
                    print(f"Vulcanary is running at {status['url']} · {status['repositories']} repositories · {status['findings']} findings · monitor {'active' if monitor.get('enabled') else 'paused'}")
                else:
                    print(f"Vulcanary is stopped · {status['repositories']} repositories configured")
                    return 1
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        return 0
    if argv and argv[0] == "update-check":
        argparse.ArgumentParser(prog="vulcanary update-check", description="Check GitHub for a newer Vulcanary release without installing it.").parse_args(argv[1:])
        try:
            from .updates import check_for_update
            update = check_for_update()
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f"error: update check failed: {error}", file=sys.stderr)
            return 2
        print(f"Vulcanary {update['current']} is installed. Latest: {update['latest']}.")
        if update["update_available"]:
            print(f"Update available: {update['url']}")
            return 1
        print("You are up to date.")
        return 0
    if argv and argv[0] == "dashboard":
        args = dashboard_parser().parse_args(argv[1:])
        from .dashboard import serve
        if args.monitor_interval is not None and args.monitor_interval != 0 and not 30 <= args.monitor_interval <= 86_400:
            dashboard_parser().error("--monitor-interval must be 0 or between 30 and 86400")
        return serve(args.host, args.port, args.repository, open_browser=not args.no_open, monitor_interval=args.monitor_interval, history_secrets=args.history_secrets, gitleaks_executable=args.gitleaks_executable)
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
        imported = [finding for scanner in ("semgrep", "gitleaks", "trivy", "checkov", "zap", "prowler", "sarif") for report in getattr(args, f"{scanner.replace('-', '_')}_json") for finding in import_report(scanner, report, root)]
        imported += [finding for report in args.trivy_image_json for finding in import_report("trivy-image", report, root)]
    except AdapterError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    imported = [
        finding for finding in imported
        if not is_excluded(finding.path, config)
        and finding.rule_id not in config.ignored_rules
        and not config.is_suppressed(finding.fingerprint)
    ]
    imported = list({finding.fingerprint: finding for finding in imported}.values())
    findings = findings + imported
    dependency_state = discover_dependency_state(root) if not args.offline or args.sbom or args.spdx else ([], [])
    packages, _unresolved = dependency_state
    if not args.offline:
        dependency_findings, warning = scan_dependencies(root, discovery=dependency_state)
        dependency_findings = [
            finding for finding in dependency_findings
            if not config.is_suppressed(finding.fingerprint)
            and not any(config.is_suppressed(alias) for alias in finding.metadata.get("legacy_fingerprints", []))
        ]
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
        write_cyclonedx(cyclonedx_document(root.name, packages, [finding.to_dict() for finding in findings]), args.sbom)
    if args.spdx:
        write_spdx(spdx_document(root.name, packages, [finding.to_dict() for finding in findings]), args.spdx)
    if args.openvex:
        write_openvex(openvex_document(root.name, [finding.to_dict() for finding in findings]), args.openvex)
    if args.ruleset_manifest:
        args.ruleset_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if args.provenance:
        artifacts = [path for path in (args.json_path, args.sarif, args.sbom, args.spdx, args.openvex, args.ruleset_manifest) if path]
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
    if args.github_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not summary_path:
            print("error: --github-summary requires GITHUB_STEP_SUMMARY", file=sys.stderr)
            return 2
        with Path(summary_path).open("a", encoding="utf-8") as summary:
            summary.write(render_markdown_summary(policy_findings, root.name) + "\n")
    blocked = any(f.severity >= config.fail_on for f in policy_findings)
    return 0 if args.no_fail or not blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
