import json
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import transport_tests as transport


class TransportTests(unittest.TestCase):
    def test_real_sockets_commit_and_response_loss_are_distinct(self):
        result = transport.run('a' * 64, authorized=True)
        self.assertEqual(result['state'], 'PASS')
        self.assertEqual(result['counts']['PASS'], 3)
        for row in result['scenarios']:
            first, second = row['events'][:2]
            self.assertEqual(first['client_outcome'], 'uncertain')
            self.assertEqual(first['committed_writes'], 0 if row['id'] == 'before-upload-commit' else 1)
            self.assertEqual(second['client_outcome'], 'acknowledged')
            self.assertEqual(second['committed_writes'], 1)
            self.assertEqual(row['cleanup'], 'complete')

    def test_deliberate_duplicate_write_is_caught_on_both_retry_paths(self):
        for name in ('lost-upload-response', 'lost-completion-response'):
            with self.subTest(name=name):
                result = transport.scenario(name, broken_duplicates=True)
                self.assertEqual(result['state'], 'FAIL')
                self.assertEqual(result['events'][1]['committed_writes'], 2)
                self.assertEqual(result['cleanup'], 'complete')

    def test_missing_authorization_never_binds(self):
        with patch.object(transport, '_Server', side_effect=AssertionError('must not bind')):
            with self.assertRaises(ValueError):
                transport.run('a' * 64)
            with self.assertRaises(ValueError):
                transport.run('bad', authorized=True)

    def test_socket_failure_is_blocked_not_pass(self):
        with patch.object(transport, '_Server', side_effect=OSError('private path or token')):
            result = transport.run('a' * 64, authorized=True)
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertEqual(result['counts']['BLOCKED'], 3)
        self.assertNotIn('private path', json.dumps(result))

    def test_unknown_path_or_wrong_run_cannot_write(self):
        with tempfile.TemporaryDirectory() as directory:
            with transport._relay(Path(directory), 'lost-upload-response') as server:
                client = transport.HTTPConnection('127.0.0.1', server.server_port, timeout=1)
                try:
                    client.request('POST', '/upload', body=b'', headers={'X-Synthetic-Run': 'wrong'})
                    response = client.getresponse()
                    self.assertEqual(response.status, 403)
                    response.read()
                    self.assertEqual(transport._counts(server), {})
                finally:
                    client.close()

    def test_report_is_sanitized_and_cli_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'review'
            args = ['--authorize-owned-loopback', '--manifest-sha256', 'a'*64, '--output', str(output)]
            self.assertEqual(transport.main(args), 0)
            for file in output.iterdir():
                content = file.read_text()
                self.assertNotIn(directory, content)
                self.assertNotIn('X-Synthetic-Run', content)
                self.assertNotIn('127.0.0.1', content)
            with patch.object(transport, 'run', side_effect=AssertionError('must not execute')):
                self.assertEqual(transport.main(args), 2)

    def test_incorrect_acknowledgment_and_cleanup_fail_closed(self):
        with patch.object(transport, '_request', return_value='acknowledged'):
            self.assertEqual(transport.scenario('lost-upload-response')['state'], 'FAIL')
        original = transport._relay
        @contextmanager
        def failed_cleanup(*args):
            with original(*args) as server:
                yield server
            raise RuntimeError('cleanup failed')
        with patch.object(transport, '_relay', failed_cleanup):
            result = transport.scenario('lost-upload-response')
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertEqual(result['cleanup'], 'unconfirmed')


if __name__ == '__main__':
    unittest.main()
