from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config
from .reporters import render_console, write_json, write_sarif
from .scanners import scan


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="vulcanary", description="Scan a repository for security risks.")
    result.add_argument("path", nargs="?", default=".", help="Repository to scan")
    result.add_argument("--config", type=Path, help="Configuration JSON path")
    result.add_argument("--json", type=Path, dest="json_path", help="Write normalized JSON report")
    result.add_argument("--sarif", type=Path, help="Write SARIF 2.1 report")
    result.add_argument("--no-fail", action="store_true", help="Always exit successfully")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: repository does not exist: {root}", file=sys.stderr)
        return 2
    config = Config.load(root, args.config)
    findings = scan(root, config)
    print(render_console(findings))
    if args.json_path:
        write_json(findings, args.json_path)
    if args.sarif:
        write_sarif(findings, args.sarif)
    blocked = any(f.severity >= config.fail_on for f in findings)
    return 0 if args.no_fail or not blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())
