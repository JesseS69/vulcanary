"""Internal subprocess fixture for rehearse_upgrade; requires an isolated home."""
import json
from pathlib import Path
import sys
from unittest.mock import patch

from vulcanary.config import Config
from vulcanary.dashboard import DashboardState, remediation_receipt_valid
from vulcanary.local_app import configure_app, load_app_config, save_app_config
from vulcanary.scanners import scan
from vulcanary.version import __version__


def main():
    mode, directory, receipt_path, version = sys.argv[1:]
    root = Path(directory).resolve()
    assert Path.home().resolve() == root, "Refuse to touch a non-isolated home"
    assert __version__ == version
    repo = root / "synthetic-repository"
    history = root / ".vulcanary/dashboard-history.json"
    config_path = root / ".vulcanary/app.json"
    if mode == "seed":
        repo.mkdir()
        (repo / "app.py").write_text("eval(untrusted)\n", encoding="utf-8")
        (repo / ".vulcanary.json").write_text(json.dumps({"ignored_fingerprints": ["synthetic-suppression"]}), encoding="utf-8")
        configure_app([repo], 900)
        state = DashboardState(history)
        with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)), patch("vulcanary.dashboard._git_identity", return_value=(None, None)):
            state.scan_repository(repo)
        receipt = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
        state.remediation_audit.append(receipt)
        state.history_acknowledgements = {str(repo): {"synthetic-exposure": {"owner": "test-team", "acknowledged_at": "2026-01-01", "rotation_asserted": True}}}
        state._persist_history()
        expected = {"history": json.loads(history.read_text(encoding="utf-8")),
                    "config": json.loads(config_path.read_text(encoding="utf-8")),
                    "repository_config": (repo / ".vulcanary.json").read_bytes().hex(),
                    "fingerprints": [item.fingerprint for item in scan(repo, Config.load(repo))]}
        (root / "expected.json").write_text(json.dumps(expected), encoding="utf-8")
    else:
        expected = json.loads((root / "expected.json").read_text(encoding="utf-8"))
        assert json.loads(config_path.read_text(encoding="utf-8")) == expected["config"]
        assert (repo / ".vulcanary.json").read_bytes().hex() == expected["repository_config"]
        assert [item.fingerprint for item in scan(repo, Config.load(repo))] == expected["fingerprints"]
        state = DashboardState(history)
        assert getattr(state, "persistence_error", None) is None
        assert all(remediation_receipt_valid(item) for item in state.remediation_audit)
        state._persist_history()
        actual = json.loads(history.read_text(encoding="utf-8"))
        for key, value in expected["history"].items():
            assert actual[key] == value, f"State changed: {key}"
        save_app_config(load_app_config())
        assert json.loads(config_path.read_text(encoding="utf-8")) == expected["config"]


if __name__ == "__main__":
    main()
