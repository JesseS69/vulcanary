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
        "history_secrets_enabled": False, "gitleaks_executable": None,
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
    if not isinstance(result.get("history_secrets_enabled"), bool):
        raise ValueError("Invalid local app configuration: history_secrets_enabled must be a boolean")
    executable = result.get("gitleaks_executable")
    if executable is not None and (not isinstance(executable, str) or not Path(executable).is_absolute()):
        raise ValueError("Invalid local app configuration: gitleaks_executable must be an absolute path")
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


def export_app_config(destination: Path) -> Path:
    config = load_app_config()
    document = {
        "format": "vulcanary-config", "version": 1,
        "repositories": config["repositories"], "monitor_interval": config["monitor_interval"],
        "host": config["host"], "port": config["port"],
        "history_secrets_enabled": config["history_secrets_enabled"],
        "gitleaks_executable": config["gitleaks_executable"],
    }
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    temporary.replace(destination)
    return destination


def import_app_config(source: Path) -> dict:
    try:
        document = json.loads(source.expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as error:
        raise ValueError(f"Invalid configuration backup: {error}") from error
    allowed = {"format", "version", "repositories", "monitor_interval", "host", "port", "history_secrets_enabled", "gitleaks_executable"}
    if not isinstance(document, dict) or set(document) - allowed or document.get("format") != "vulcanary-config" or document.get("version") != 1:
        raise ValueError("Invalid or unsupported Vulcanary configuration backup")
    repositories = document.get("repositories")
    if not isinstance(repositories, list) or any(not isinstance(item, str) for item in repositories):
        raise ValueError("Configuration backup repositories must be a string array")
    if document.get("host") not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Configuration backup host must be loopback")
    interval = document.get("monitor_interval")
    port = document.get("port")
    if not isinstance(interval, int) or interval != 0 and not 30 <= interval <= 86_400:
        raise ValueError("Configuration backup monitor interval must be 0 or 30-86400")
    if not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("Configuration backup port must be between 1 and 65535")
    history_enabled = document.get("history_secrets_enabled", False)
    gitleaks_executable = document.get("gitleaks_executable")
    if not isinstance(history_enabled, bool) or gitleaks_executable is not None and (not isinstance(gitleaks_executable, str) or not Path(gitleaks_executable).is_absolute()):
        raise ValueError("Configuration backup history scanner settings are invalid")
    if history_enabled:
        from .history_secrets import validate_executable
        gitleaks_executable = str(validate_executable(gitleaks_executable or ""))
    resolved = []
    for item in repositories:
        root = Path(item).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"Repository does not exist: {root}")
        resolved.append(str(root))
    current = load_app_config()
    configured = current | {
        "repositories": list(dict.fromkeys(resolved)), "monitor_interval": interval,
        "host": document["host"], "port": port, "control_token": current["control_token"],
        "history_secrets_enabled": history_enabled, "gitleaks_executable": gitleaks_executable,
    }
    save_app_config(configured)
    return configured


def configure_app(repositories: list[Path], interval: int, port: int = 8765, history_secrets_enabled: bool = False, gitleaks_executable: Path | None = None) -> dict:
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
    executable = str(gitleaks_executable.expanduser().resolve()) if gitleaks_executable else None
    if history_secrets_enabled:
        from .history_secrets import validate_executable
        executable = str(validate_executable(executable or ""))
    config = existing | {"repositories": list(dict.fromkeys(resolved)), "monitor_interval": interval, "port": port, "history_secrets_enabled": history_secrets_enabled, "gitleaks_executable": executable}
    save_app_config(config)
    return config


def save_watched_repositories(repositories: list[str]) -> Path:
    resolved = []
    for repository in repositories:
        root = Path(repository).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"Repository does not exist: {root}")
        resolved.append(str(root))
    config = load_app_config()
    config["repositories"] = list(dict.fromkeys(resolved))
    return save_app_config(config)


def add_watched_repositories(repositories: list[str]) -> Path:
    """Add repositories without discarding the user's existing watch list."""
    config = load_app_config()
    combined = [*config.get("repositories", []), *repositories]
    return save_watched_repositories(combined)


def service_status(config: dict | None = None, timeout: float = 1.5) -> dict:
    current = config or load_app_config()
    url = f"http://{current['host']}:{current['port']}"
    state_url = f"{url}/api/state"
    request = Request(state_url, headers={"X-Vulcanary-Control": current["control_token"]})
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310 -- URL is validated loopback configuration only.
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
    if current.get("history_secrets_enabled"):
        arguments.extend(["--history-secrets", "--gitleaks-executable", current["gitleaks_executable"]])
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
