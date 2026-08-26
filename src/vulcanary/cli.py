from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config
from .reporters import render_console, write_json, write_sarif
from .scanners import scan
from .dependencies import scan_dependencies


def scan_parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary", description="Scan a repository for security risks.")
    result.add_argument("path", nargs="?", default=".", help="Repository to scan")
    result.add_argument("--config", type=Path, help="Configuration JSON path")
    result.add_argument("--json", type=Path, dest="json_path", help="Write normalized JSON report")
    result.add_argument("--sarif", type=Path, help="Write SARIF 2.1 report")
    result.add_argument("--no-fail", action="store_true", help="Always exit successfully")
    result.add_argument("--offline", action="store_true", help="Skip OSV dependency advisory queries")
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
    config = Config.load(root, args.config)
    findings = scan(root, config)
    if not args.offline:
        dependency_findings, warning = scan_dependencies(root)
        dependency_findings = [finding for finding in dependency_findings if finding.fingerprint not in config.ignored_fingerprints]
        findings = sorted(findings + dependency_findings, key=lambda f: (-int(f.severity), f.path, f.line))
        if warning:
            print(f"warning: {warning}", file=sys.stderr)
    print(render_console(findings))
    if args.json_path:
        write_json(findings, args.json_path)
    if args.sarif:
        write_sarif(findings, args.sarif)
    blocked = any(f.severity >= config.fail_on for f in findings)
    return 0 if args.no_fail or not blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
