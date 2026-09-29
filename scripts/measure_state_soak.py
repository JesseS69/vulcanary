"""Synthetic offline retention measurement; never touches the live app directory."""
import json
import platform
import tempfile
import time
import tracemalloc
from pathlib import Path
from unittest.mock import patch

from vulcanary.dashboard import DashboardState


def measure():
    windows = []
    with tempfile.TemporaryDirectory() as directory, patch("vulcanary.dashboard.scan_dependencies", new=lambda *args, **kwargs: ([], None)), patch("vulcanary.dashboard._git_identity", new=lambda *args: (None, None)):
        root = Path(directory)
        repo = root / "synthetic-service"
        repo.mkdir()
        (repo / "app.py").write_text("eval(untrusted)\n", encoding="utf-8")
        state = DashboardState(root / "history.json")
        tracemalloc.start()
        for window in range(3):
            started = time.perf_counter()
            for _ in range(200):
                state.scan_repository(repo)
            elapsed = time.perf_counter() - started
            current, peak = tracemalloc.get_traced_memory()
            windows.append({"scans": (window + 1) * 200, "seconds": round(elapsed, 3),
                            "mean_scan_ms": round(elapsed * 5, 3), "python_current_bytes": current,
                            "python_peak_bytes": peak, "history_bytes": state.history_path.stat().st_size,
                            "history_records": len(state.history), "pruned": dict(state.retention_pruned)})
        tracemalloc.stop()
        assert windows[-1]["history_records"] == 100
        assert abs(windows[-1]["history_bytes"] - windows[-2]["history_bytes"]) < 2048
        assert len(state.finding_first_seen) == 1
    return {"workload": "600 stable synthetic offline scans; OSV and git identity mocked",
            "python": platform.python_version(), "system": platform.system(), "windows": windows}


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
