import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from vulcanary.local_app import configure_app, export_app_config, import_app_config, load_app_config, save_watched_repositories, service_status, start_service


class LocalAppTests(unittest.TestCase):
    def test_configuration_backup_excludes_secrets_and_restores_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); app = base / "app"; repository = base / "repository"; repository.mkdir()
            backup = base / "backup.json"
            with patch("vulcanary.local_app.app_directory", return_value=app):
                configured = configure_app([repository], 900, 8877)
                original_token = configured["control_token"]
                export_app_config(backup)
                exported = json.loads(backup.read_text(encoding="utf-8"))
                self.assertNotIn("control_token", exported)
                self.assertNotIn("history", exported)
                configured = configure_app([repository], 300, 8765)
                restored = import_app_config(backup)
                self.assertEqual((restored["monitor_interval"], restored["port"]), (900, 8877))
                self.assertEqual(restored["control_token"], original_token)

    def test_invalid_backup_cannot_replace_current_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); app = base / "app"; repository = base / "repository"; repository.mkdir()
            backup = base / "bad.json"; backup.write_text('{"format":"vulcanary-config","version":1,"repositories":[],"monitor_interval":300,"host":"0.0.0.0","port":8765}', encoding="utf-8")
            with patch("vulcanary.local_app.app_directory", return_value=app):
                before = configure_app([repository], 300)
                with self.assertRaisesRegex(ValueError, "loopback"):
                    import_app_config(backup)
                self.assertEqual(load_app_config(), before)

    def test_configuration_is_validated_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "app"
            repository = Path(directory) / "repository"
            repository.mkdir()
            with patch("vulcanary.local_app.app_directory", return_value=app):
                configured = configure_app([repository, repository], 900, 8877)
                self.assertEqual(configured["repositories"], [str(repository.resolve())])
                self.assertEqual(load_app_config()["monitor_interval"], 900)
                self.assertEqual(load_app_config()["port"], 8877)
                self.assertGreaterEqual(len(load_app_config()["control_token"]), 32)
                document = json.loads((app / "app.json").read_text(encoding="utf-8"))
                self.assertNotIn("source", document)
                with self.assertRaisesRegex(ValueError, "does not exist"):
                    configure_app([Path(directory) / "missing"], 300)
                second = Path(directory) / "second"
                second.mkdir()
                save_watched_repositories([str(second)])
                self.assertEqual(load_app_config()["repositories"], [str(second.resolve())])
                self.assertEqual(load_app_config()["monitor_interval"], 900)

    def test_background_start_keeps_control_token_out_of_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "app"
            repository = Path(directory) / "repository"
            repository.mkdir()
            config = {
                "host": "127.0.0.1", "port": 8765, "monitor_interval": 300,
                "repositories": [str(repository)], "control_token": "s" * 43,
            }
            process = Mock(pid=321)
            process.poll.return_value = None
            with (
                patch("vulcanary.local_app.app_directory", return_value=app),
                patch("vulcanary.local_app.service_status", side_effect=[
                    {"running": False, "url": "http://127.0.0.1:8765", "repositories": 1},
                    {"running": True, "url": "http://127.0.0.1:8765", "repositories": 1, "findings": 0},
                ]),
                patch("vulcanary.local_app.subprocess.Popen", return_value=process) as popen,
                patch("vulcanary.local_app.time.sleep"),
            ):
                status = start_service(config)
            arguments = popen.call_args.args[0]
            options = popen.call_args.kwargs
            self.assertNotIn(config["control_token"], arguments)
            self.assertEqual(options["env"]["VULCANARY_CONTROL_TOKEN"], config["control_token"])
            self.assertIn("--monitor-interval", arguments)
            self.assertTrue(status["started"])
            self.assertEqual((app / "dashboard.pid").read_text(encoding="ascii"), "321\n")

    def test_status_fails_closed_when_service_is_unavailable(self) -> None:
        config = {"host": "127.0.0.1", "port": 8765, "repositories": [], "monitor_interval": 300, "control_token": "x" * 43}
        with patch("vulcanary.local_app.urlopen", side_effect=OSError("offline")):
            self.assertEqual(service_status(config), {
                "running": False, "url": "http://127.0.0.1:8765", "repositories": 0,
            })

    def test_status_authenticates_its_state_request(self) -> None:
        config = {"host": "127.0.0.1", "port": 8765, "repositories": [], "monitor_interval": 300, "control_token": "x" * 43}
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"summary":{"total":2},"repositories":[{}],"monitor":{}}'
        with patch("vulcanary.local_app.urlopen", return_value=response) as opened:
            self.assertTrue(service_status(config)["running"])
        self.assertEqual(opened.call_args.args[0].get_header("X-vulcanary-control"), config["control_token"])


if __name__ == "__main__":
    unittest.main()
