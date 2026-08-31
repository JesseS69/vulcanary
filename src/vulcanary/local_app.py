from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


def app_directory() -> Path:
    return Path.home() / ".vulcanary"


def config_path() -> Path:
    return app_directory() / "app.json"


def _default_config() -> dict:
    return {
        "host": "127.0.0.1", "port": 8765, "monitor_interval": 300,
        "repositories": [], "control_token": secrets.token_urlsafe(32),
    }


def load_app_config() -> dict:
    path = config_path()
    if not path.exists():
        return _default_config()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as error:
        raise ValueError(f"Invalid local app configuration: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("Invalid local app configuration: expected an object")
    result = _default_config() | value
    repositories = result.get("repositories")
    if not isinstance(repositories, list) or any(not isinstance(item, str) for item in repositories):
        raise ValueError("Invalid local app configuration: repositories must be a list of paths")
    if result.get("host") not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Invalid local app configuration: host must be loopback")
    if not isinstance(result.get("port"), int) or not 1 <= result["port"] <= 65_535:
        raise ValueError("Invalid local app configuration: port must be between 1 and 65535")
    interval = result.get("monitor_interval")
    if not isinstance(interval, int) or interval != 0 and not 30 <= interval <= 86_400:
        raise ValueError("Invalid local app configuration: monitor interval must be 0 or 30-86400")
    if not isinstance(result.get("control_token"), str) or len(result["control_token"]) < 32:
        result["control_token"] = secrets.token_urlsafe(32)
    return result


def save_app_config(config: dict) -> Path:
    directory = app_directory()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    path = config_path()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def configure_app(repositories: list[Path], interval: int, port: int = 8765) -> dict:
    resolved = []
    for repository in repositories:
        root = repository.expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"Repository does not exist: {root}")
        resolved.append(str(root))
    if interval != 0 and not 30 <= interval <= 86_400:
        raise ValueError("Monitoring interval must be 0 or between 30 and 86400 seconds")
    if not 1 <= port <= 65_535:
        raise ValueError("Port must be between 1 and 65535")
    existing = load_app_config()
    config = existing | {"repositories": list(dict.fromkeys(resolved)), "monitor_interval": interval, "port": port}
    save_app_config(config)
    return config


def service_status(config: dict | None = None, timeout: float = 1.5) -> dict:
    current = config or load_app_config()
    url = f"http://{current['host']}:{current['port']}"
    state_url = f"{url}/api/state"
    try:
        with urlopen(state_url, timeout=timeout) as response:  # nosec B310 -- URL is validated loopback configuration only.
            payload = json.loads(response.read())
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return {"running": False, "url": url, "repositories": len(current["repositories"])}
    if not isinstance(payload, dict) or not isinstance(payload.get("summary"), dict) or not isinstance(payload.get("repositories"), list):
        return {"running": False, "url": url, "repositories": len(current["repositories"])}
    return {
        "running": True, "url": url, "repositories": len(payload.get("repositories", [])),
        "findings": payload.get("summary", {}).get("total", 0), "monitor": payload.get("monitor", {}),
    }


def start_service(config: dict | None = None) -> dict:
    current = config or load_app_config()
    status = service_status(current)
    if status["running"]:
        return status | {"started": False}
    if not current["repositories"]:
        raise ValueError("No repositories are configured. Run `vulcanary setup` first.")
    directory = app_directory()
    directory.mkdir(parents=True, exist_ok=True)
    arguments = [
        sys.executable, "-m", "vulcanary", "dashboard", "--no-open", "--host", current["host"],
        "--port", str(current["port"]), "--monitor-interval", str(current["monitor_interval"]),
    ]
    for repository in current["repositories"]:
        arguments.extend(["--repository", repository])
    environment = os.environ.copy()
    environment["VULCANARY_CONTROL_TOKEN"] = current["control_token"]
    creationflags = 0
    options: dict = {"cwd": str(directory), "env": environment}
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
        options["creationflags"] = creationflags
    else:
        options["start_new_session"] = True
    log = (directory / "dashboard.log").open("ab")
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=log, stderr=log, **options)
    finally:
        log.close()
    (directory / "dashboard.pid").write_text(f"{process.pid}\n", encoding="ascii")
    for _ in range(30):
        time.sleep(0.1)
        status = service_status(current, timeout=0.3)
        if status["running"]:
            return status | {"started": True, "pid": process.pid}
        if process.poll() is not None:
            break
    raise RuntimeError(f"Vulcanary did not start. Review {directory / 'dashboard.log'}")


def stop_service(config: dict | None = None) -> dict:
    current = config or load_app_config()
    url = f"http://{current['host']}:{current['port']}/api/control/shutdown"
    request = Request(url, data=b"{}", method="POST", headers={
        "Content-Type": "application/json", "X-Vulcanary-Control": current["control_token"],
    })
    try:
        with urlopen(request, timeout=3) as response:  # nosec B310 -- URL is validated loopback configuration only.
            response.read()
    except URLError:
        return {"stopped": False, "running": False}
    for _ in range(30):
        time.sleep(0.1)
        if not service_status(current, timeout=0.2)["running"]:
            (app_directory() / "dashboard.pid").unlink(missing_ok=True)
            return {"stopped": True, "running": False}
    return {"stopped": False, "running": True}
