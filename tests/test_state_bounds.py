import copy
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from vulcanary.dashboard import DashboardState, make_handler, remediation_receipt_valid, serve
from vulcanary.local_app import configure_app, load_app_config, save_app_config
from vulcanary.state_store import RETENTION_LIMITS, StateCapacity, StateConflict, state_lock


class StateBoundsTests(unittest.TestCase):
    def test_closed_state_refuses_new_history_workers_and_mutations(self):
        state = DashboardState()
        state.history_secrets_enabled = True
        state.gitleaks_executable = Path("synthetic-tool")
        state.close()
        with patch("vulcanary.dashboard.threading.Thread") as thread:
            self.assertFalse(state.scan_all_history_async([Path("synthetic-repository")]))
            state.start_monitor()
            thread.assert_not_called()
        with self.assertRaisesRegex(ValueError, "closing"):
            state.record_remediation("test", {})
        self.assertEqual(state.remediation_audit, [])

    def test_retained_export_requires_auth_and_preserves_receipt_proof(self):
        state = DashboardState()
        state.control_token = "synthetic-export-token"
        state.remediation_audit = [json.loads((Path(__file__).parent / "contracts/golden/receipt.json").read_text(encoding="utf-8"))]
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/api/history/export"
            with self.assertRaises(HTTPError) as denied:
                urlopen(url, timeout=5)
            self.assertEqual(denied.exception.code, 403)
            denied.exception.close()
            with urlopen(Request(url, headers={"X-Vulcanary-Control": state.control_token}), timeout=5) as response:
                document = json.load(response)
            self.assertEqual(document, state._history_payload())
            self.assertTrue(remediation_receipt_valid(document["remediation_audit"][0]))
            self.assertNotIn(state.control_token, json.dumps(document))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_retention_is_visible_and_leaves_continuity_and_seals_intact(self):
        receipt = json.loads((Path(__file__).parent / "contracts/golden/receipt.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory) / "history.json")
            state.finding_first_seen = {"active": "2026-01-01"}
            state.history_acknowledgements = {"repo": {"exposure": {"owner": "team"}}}
            for key, limit in RETENTION_LIMITS.items():
                setattr(state, key, [copy.deepcopy(receipt) if key == "remediation_audit" else {"index": i} for i in range(limit + 7)])
            state._persist_history()
            restarted = DashboardState(state.history_path)
            self.assertEqual(restarted.retention_pruned, {key: 7 for key in RETENTION_LIMITS})
            self.assertEqual(restarted.finding_first_seen, state.finding_first_seen)
            self.assertEqual(restarted.history_acknowledgements, state.history_acknowledgements)
            for key, limit in RETENTION_LIMITS.items():
                self.assertEqual(len(getattr(restarted, key)), limit)
            self.assertTrue(all(remediation_receipt_valid(item) for item in restarted.remediation_audit))

    def test_failure_after_scan_mutations_rolls_back_every_transaction_field(self):
        with tempfile.TemporaryDirectory() as directory, patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
            root = Path(directory); repo = root / "repo"; repo.mkdir()
            source = repo / "app.py"; source.write_text("eval(untrusted)\n", encoding="utf-8")
            state = DashboardState(root / "history.json")
            state.scan_repository(repo)
            before = copy.deepcopy(state._history_payload()); disk = state.history_path.read_bytes()
            public_before = state.repositories[str(repo.resolve())].to_dict()
            source.write_text("pass\n", encoding="utf-8")
            with patch.object(state, "_persist_history", side_effect=ValueError("injected after resolution mutation")):
                with self.assertRaises(ValueError):
                    state.scan_repository(repo)
            self.assertEqual(state._history_payload(), before)
            self.assertEqual(state.history_path.read_bytes(), disk)
            self.assertEqual(state.repositories[str(repo.resolve())].to_dict(), public_before)
            state.scan_repository(repo)
            self.assertEqual(len(state.resolved_findings), 1)

    def test_capacity_refusal_rolls_back_without_pruning_continuity(self):
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory) / "history.json")
            state._persist_history(); before = state.history_path.read_bytes()
            with patch("vulcanary.dashboard.HISTORY_LIMIT_BYTES", len(before) + 10):
                with self.assertRaises(StateCapacity):
                    state.record_remediation("test", {"large": "x" * 2000})
            self.assertEqual(state.remediation_audit, [])
            self.assertEqual(state.history_path.read_bytes(), before)
            self.assertEqual(state.persistence_error["code"], "history_capacity_reached")

    def test_stale_history_and_config_writers_cannot_overwrite_each_other(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = DashboardState(root / "history.json"); second = DashboardState(first.history_path)
            first.configure_monitor(False, 900)
            with self.assertRaises(StateConflict):
                second.configure_monitor(True, 600)
            self.assertEqual(second.monitor_interval_seconds, 300)
            self.assertEqual(DashboardState(first.history_path).monitor_interval_seconds, 900)
            with patch.object(Path, "home", return_value=root):
                configure_app([root], 300)
                a, b = load_app_config(), load_app_config()
                a["monitor_interval"] = 900; save_app_config(a)
                b["monitor_interval"] = 600
                with self.assertRaises(StateConflict): save_app_config(b)
                self.assertEqual(load_app_config()["monitor_interval"], 900)

    def test_os_lock_excludes_another_process_and_releases_after_death(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.lock"
            child = "from pathlib import Path; import sys; from vulcanary.state_store import state_lock;\nwith state_lock(Path(sys.argv[1])): pass\n"
            with state_lock(path):
                result = subprocess.run([sys.executable, "-c", child, str(path)], capture_output=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"StateConflict", result.stderr)
            child = "from pathlib import Path; import os,sys; from vulcanary.state_store import state_lock;\nwith state_lock(Path(sys.argv[1])): os._exit(73)\n"
            result = subprocess.run([sys.executable, "-c", child, str(path)], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 73)
            with state_lock(path): pass

    def test_shutdown_while_initial_scan_is_blocked_never_starts_monitor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); entered, release, finished = threading.Event(), threading.Event(), threading.Event()
            captured = {}; real_start = DashboardState.start_monitor
            def scan(state, _):
                captured["state"] = state; entered.set()
                if not release.wait(5): raise AssertionError("No release")
            def start(state):
                real_start(state); finished.set()
            class Server:
                server_port = 8765
                def __init__(self, *_): pass
                def serve_forever(self):
                    if not entered.wait(5): raise AssertionError("No initial scan")
                def server_close(self): release.set()
                def shutdown(self): pass
            with patch.object(Path, "home", return_value=root), patch("vulcanary.dashboard.ThreadingHTTPServer", Server), patch.object(DashboardState, "scan_repository", scan), patch.object(DashboardState, "start_monitor", start), redirect_stdout(io.StringIO()):
                serve("127.0.0.1", 8765, [root], open_browser=False)
                self.assertTrue(finished.wait(5))
            state = captured["state"]
            self.assertTrue(state._closing.is_set())
            self.assertIsNone(state._monitor_thread)

    def test_stable_repository_soak_plateaus_without_identity_loss(self):
        with tempfile.TemporaryDirectory() as directory, patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)), patch("vulcanary.dashboard._git_identity", return_value=(None, None)):
            root = Path(directory); repo = root / "repo"; repo.mkdir()
            (repo / "app.py").write_text("eval(untrusted)\n", encoding="utf-8")
            state = DashboardState(root / "history.json")
            state.scan_repository(repo); original = dict(state.finding_first_seen)
            for _ in range(220): state.scan_repository(repo)
            size = state.history_path.stat().st_size
            for _ in range(220): state.scan_repository(repo)
            self.assertLess(abs(state.history_path.stat().st_size - size), 2048)
            self.assertEqual(len(state.history), 100)
            self.assertEqual(state.retention_pruned["history"], 341)
            self.assertEqual(state.finding_first_seen, original)
            self.assertEqual(DashboardState(state.history_path).finding_first_seen, original)
