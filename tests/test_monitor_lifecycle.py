import contextlib
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary.dashboard import DashboardState, serve
from vulcanary.local_app import configure_app, load_app_config, remove_watched_repository


class MonitorLifecycleTests(unittest.TestCase):
    def test_real_startup_failure_remains_retryable_and_clears_on_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo = root / "repo"; repo.mkdir()
            config = repo / ".vulcanary.json"
            config.write_text("{broken", encoding="utf-8")
            ready = threading.Event(); captured = {}

            class Server:
                server_port = 8765
                def __init__(self, *_): pass
                def serve_forever(self):
                    if not ready.wait(5):
                        raise AssertionError("Startup never finished")
                def shutdown(self): pass
                def server_close(self): pass

            def started(state):
                captured["state"] = state
                ready.set()

            with patch.object(Path, "home", return_value=root), patch("vulcanary.dashboard.ThreadingHTTPServer", Server), patch.object(DashboardState, "start_monitor", started), patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)), contextlib.redirect_stdout(io.StringIO()):
                serve("127.0.0.1", 8765, [repo], open_browser=False)
                state = captured["state"]
                self.assertEqual(state.pending_repositories, {str(repo)})
                self.assertEqual(state.rescan_all(), [])
                self.assertEqual(state.rescan_errors[0]["code"], "repository_scan_failed")
                self.assertEqual(load_app_config()["repositories"], [str(repo)])
                config.write_text("{}", encoding="utf-8")
                self.assertEqual(len(state.rescan_all()), 1)
                self.assertEqual(state.pending_repositories, set())
                self.assertEqual(state.startup_errors, [])
                self.assertIsNone(state.monitor_error)

    def test_removing_pending_target_preserves_unavailable_configured_peers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target, peer = root / "target", root / "peer"
            target.mkdir(); peer.mkdir()
            with patch.object(Path, "home", return_value=root):
                configured = configure_app([target, peer], 300)
                peer.rmdir()  # Simulate a disconnected path, not a requested removal.
                state = DashboardState()
                state.pending_repositories.add(str(target))
                state.remove_repository(str(target))
                remove_watched_repository(str(target))
                self.assertEqual(state.pending_repositories, set())
                self.assertEqual(load_app_config()["repositories"], [str(peer)])
                self.assertEqual(load_app_config()["control_token"], configured["control_token"])

    def test_monitor_stop_during_active_cycle_requires_completion_before_restart(self):
        state = DashboardState()
        state.monitor_interval_seconds = 0.01  # Test clock only; public config still requires 30s.
        entered, release, second = threading.Event(), threading.Event(), threading.Event()
        calls = []

        def cycle():
            calls.append(1)
            if len(calls) == 1:
                entered.set()
                if not release.wait(8):
                    raise AssertionError("Test never released active scan")
            else:
                second.set()
                state._monitor_stop.set()

        with patch.object(state, "rescan_all", side_effect=cycle):
            try:
                state.start_monitor()
                self.assertTrue(entered.wait(3))
                original_thread = state._monitor_thread
                state.stop_monitor()
                self.assertTrue(original_thread.is_alive())
                with self.assertRaisesRegex(ValueError, "still stopping"):
                    state.start_monitor()
                self.assertIs(state._monitor_thread, original_thread)
                release.set(); original_thread.join(3)
                self.assertFalse(original_thread.is_alive())
                state.start_monitor()
                self.assertTrue(second.wait(3))
                self.assertIsNot(state._monitor_thread, original_thread)
            finally:
                release.set()
                state.stop_monitor()
        self.assertEqual(len(calls), 2)

    def test_process_exit_before_replace_preserves_state_and_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.object(Path, "home", return_value=root):
                configure_app([root], 900)
                state = DashboardState(root / "history.json")
                state.finding_first_seen = {"fixture": "2026-01-01T00:00:00+00:00"}
                receipt = json.loads((Path(__file__).parent / "contracts/golden/receipt.json").read_text(encoding="utf-8"))
                state.remediation_audit = [receipt]
                state.configure_monitor(False, 900)
                original_history = (root / "history.json").read_bytes()
                original_config = (root / ".vulcanary/app.json").read_bytes()
                child = (
                    "import os,sys\nfrom pathlib import Path\n"
                    "from vulcanary.dashboard import DashboardState\n"
                    "from vulcanary.local_app import load_app_config,save_app_config\n"
                    "root=Path(sys.argv[1]); Path.home=classmethod(lambda cls: root)\n"
                    "state=DashboardState(root/'history.json'); config=load_app_config()\n"
                    "Path.replace=lambda *args,**kwargs: os._exit(71)\n"
                    "if sys.argv[2]=='history': state.configure_monitor(True,300)\n"
                    "else: save_app_config(config | {'repositories': []})\n"
                )
                for kind in ("history", "config"):
                    completed = subprocess.run([sys.executable, "-c", child, str(root), kind], capture_output=True, timeout=15)
                    self.assertEqual(completed.returncode, 71, completed.stderr.decode(errors="replace"))
                self.assertEqual((root / "history.json").read_bytes(), original_history)
                self.assertEqual((root / ".vulcanary/app.json").read_bytes(), original_config)
                restarted = DashboardState(root / "history.json")
                self.assertEqual(restarted.finding_first_seen, state.finding_first_seen)
                self.assertEqual(restarted.remediation_audit, [receipt])
                self.assertFalse(restarted.monitor_enabled)
                restarted._persist_history()
                self.assertIsNone(restarted.persistence_error)
