from __future__ import annotations

import json
import threading
import webbrowser
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlparse

from .config import Config
from .scanners import scan


@dataclass
class RepositoryScan:
    repository: str
    name: str
    scanned_at: str
    duration_ms: int
    findings: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


class DashboardState:
    def __init__(self, history_path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self.repositories: dict[str, RepositoryScan] = {}
        self.history_path = history_path
        self.history: list[dict] = []
        if history_path and history_path.exists():
            try:
                payload = json.loads(history_path.read_text(encoding="utf-8"))
                self.history = list(payload.get("history", []))[-100:]
            except (OSError, ValueError, TypeError):
                self.history = []

    def scan_repository(self, path: Path) -> RepositoryScan:
        import time
        root = path.resolve()
        if not root.is_dir():
            raise ValueError(f"Repository does not exist: {root}")
        started = time.perf_counter()
        findings = scan(root, Config.load(root))
        result = RepositoryScan(
            repository=str(root),
            name=root.name,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=round((time.perf_counter() - started) * 1000),
            findings=[finding.to_dict() for finding in findings],
        )
        with self._lock:
            self.repositories[str(root)] = result
            self.history.append({
                "repository": result.repository,
                "name": result.name,
                "scanned_at": result.scanned_at,
                "duration_ms": result.duration_ms,
                "finding_count": len(result.findings),
            })
            self.history = self.history[-100:]
            if self.history_path:
                try:
                    self.history_path.parent.mkdir(parents=True, exist_ok=True)
                    self.history_path.write_text(json.dumps({"history": self.history}, indent=2) + "\n", encoding="utf-8")
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
        for item in findings:
            categories[item["category"]] = categories.get(item["category"], 0) + 1
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repositories": scans,
            "findings": findings,
            "history": list(reversed(self.history)),
            "summary": {"total": len(findings), "counts": counts, "categories": categories},
        }


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

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/state":
                self._json(state.snapshot())
                return
            assets = {
                "/": ("index.html", "text/html"),
                "/app.js": ("app.js", "text/javascript"),
                "/styles.css": ("styles.css", "text/css"),
                "/brand.css": ("brand.css", "text/css"),
                "/forge.css": ("forge.css", "text/css"),
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
            if urlparse(self.path).path != "/api/scan":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 16_384:
                    raise ValueError("Request is too large")
                payload = json.loads(self.rfile.read(length))
                repository = Path(payload["repository"])
                result = state.scan_repository(repository)
                self._json({"scan": result.to_dict(), "state": state.snapshot()})
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
