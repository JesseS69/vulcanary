import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary.dashboard import DashboardState
from vulcanary.local_app import configure_app, load_app_config, save_app_config


class StateRecoveryTests(unittest.TestCase):
    def test_partial_rescan_preserves_failed_snapshot_and_scans_later_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.mkdir(); second.mkdir()
            (first / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            history = root / "history.json"
            with patch("vulcanary.local_app.app_directory", return_value=root / "local-app"), patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                configure_app([first, second], 300)
                config_before = (root / "local-app" / "app.json").read_bytes()
                state = DashboardState(history)
                state.scan_repository(first); state.scan_repository(second)
                previous = copy.deepcopy(state.finding_snapshots[str(first.resolve())])
                first_seen = copy.deepcopy(state.finding_first_seen)
                previous_scan = state.repositories[str(first.resolve())]
                (first / ".vulcanary.json").write_text("{broken", encoding="utf-8")
                (second / "app.py").write_text("eval(other_input)\n", encoding="utf-8")
                results = state.rescan_all()
                self.assertEqual([r.repository for r in results], [str(second.resolve())])
                self.assertIs(state.repositories[str(first.resolve())], previous_scan)
                self.assertEqual(state.finding_snapshots[str(first.resolve())], previous)
                for fingerprint, seen in first_seen.items():
                    self.assertEqual(state.finding_first_seen[fingerprint], seen)
                self.assertEqual(state.resolved_findings, [])
                self.assertEqual(len(results[0].findings), 1)
                self.assertEqual(state.rescan_errors[0]["repository"], str(first.resolve()))
                self.assertIn("stale", state.monitor_error)
                self.assertFalse(state._rescan_lock.locked())
                self.assertEqual((root / "local-app" / "app.json").read_bytes(), config_before)
                restored = DashboardState(history)
                self.assertEqual(restored.finding_snapshots[str(first.resolve())], previous)
                (first / ".vulcanary.json").write_text("{}", encoding="utf-8")
                self.assertEqual(len(state.rescan_all()), 2)
                self.assertEqual(state.rescan_errors, [])
                self.assertIsNone(state.monitor_error)

    def test_history_write_and_replace_failures_preserve_bytes_and_retry(self):
        for operation in ("write_text", "replace"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                history = Path(directory) / "history.json"
                state = DashboardState(history)
                state.configure_monitor(False, 900)
                original = history.read_bytes()
                state.history.append({"repository": "new"})
                with patch.object(Path, operation, side_effect=OSError("injected disk failure")):
                    state._persist_history()
                self.assertEqual(history.read_bytes(), original)
                self.assertEqual(list(history.parent.glob("*.tmp")), [])
                self.assertEqual(state.snapshot()["diagnostics"]["persistence_error"]["code"], "history_write_failed")
                self.assertEqual(state.snapshot()["diagnostics"]["history"], "memory-only")
                state._persist_history()
                self.assertIsNone(state.persistence_error)
                restored = DashboardState(history)
                self.assertEqual(restored.history, state.history)
                self.assertFalse(restored.monitor_enabled)
                self.assertEqual(restored.monitor_interval_seconds, 900)

    def test_corrupt_history_is_never_overwritten_and_recovery_requires_restart(self):
        for content in (b"{partial", b"\xff", b"[]", b'{"history": "bad"}', b'{"monitor": []}'):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                history = Path(directory) / "history.json"
                history.write_bytes(content)
                state = DashboardState(history)
                self.assertEqual(state.persistence_error["code"], "history_load_failed")
                state.configure_monitor(False, 900)
                self.assertEqual(history.read_bytes(), content)
                # Simulate operator recovery of the original file; this process remains blocked.
                history.write_text('{"history": [], "monitor": {"enabled": false, "interval_seconds": 900}}', encoding="utf-8")
                recovered = history.read_bytes()
                state._persist_history()
                self.assertEqual(history.read_bytes(), recovered)
                restarted = DashboardState(history)
                self.assertIsNone(restarted.persistence_error)
                restarted.history.append({"repository": "after-recovery"})
                restarted._persist_history()
                self.assertEqual(DashboardState(history).history, restarted.history)

    def test_unreadable_history_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.json"
            history.write_text('{"history": []}', encoding="utf-8")
            original = history.read_bytes()
            with patch.object(Path, "read_text", side_effect=PermissionError("injected")):
                state = DashboardState(history)
            state._persist_history()
            self.assertEqual(history.read_bytes(), original)
            self.assertEqual(state.persistence_error["code"], "history_load_failed")

    def test_partial_temporary_write_never_replaces_durable_history(self):
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.json"
            state = DashboardState(history)
            state._persist_history()
            original = history.read_bytes()
            real_write = Path.write_text

            def partial_write(path, content, **kwargs):
                real_write(path, content[:20], **kwargs)
                raise OSError("disk full after partial write")

            with patch.object(Path, "write_text", partial_write):
                state._persist_history()
            self.assertEqual(history.read_bytes(), original)
            self.assertEqual(list(history.parent.glob("*.tmp")), [])
            self.assertIsNone(DashboardState(history).persistence_error)

    def test_configuration_failed_atomic_write_preserves_token_and_watch_list(self):
        for operation in ("write_text", "replace"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch("vulcanary.local_app.app_directory", return_value=root / "local-app"):
                    original = configure_app([root], 300)
                    path = root / "local-app" / "app.json"
                    before = path.read_bytes()
                    with patch.object(Path, operation, side_effect=OSError("injected")):
                        with self.assertRaises(OSError):
                            save_app_config(original | {"repositories": []})
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual(list(path.parent.glob("*.tmp")), [])
                    self.assertEqual(load_app_config()["control_token"], original["control_token"])
                    self.assertEqual(load_app_config()["repositories"], original["repositories"])


if __name__ == "__main__":
    unittest.main()
