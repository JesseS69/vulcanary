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
        self.assertEqual(result['counts']['PASS'], 5)
        self.assertEqual(result['schema'], 'vulcanary.synthetic-transport-run.v2')
        for row in result['scenarios']:
            first, second = row['events'][:2]
            self.assertEqual(first['client_outcome'], row['expected']['first_client_outcome'])
            self.assertEqual(first['committed_writes'], row['expected']['first_committed_writes'])
            self.assertEqual(second['client_outcome'], 'acknowledged')
            self.assertEqual(second['committed_writes'], 1)
            self.assertEqual(row['cleanup'], 'complete')

    def test_deliberate_duplicate_write_is_caught_on_both_retry_paths(self):
        for name in ('lost-upload-response', 'lost-completion-response', 'stalled-after-upload-commit'):
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
        self.assertEqual(result['counts']['BLOCKED'], 5)
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

    def test_stalls_reach_handler_and_preserve_timeout_before_success(self):
        for name in ('stalled-before-upload-commit', 'stalled-after-upload-commit'):
            result = transport.scenario(name)
            self.assertEqual(result['state'], 'PASS')
            self.assertEqual(result['events'][0]['client_outcome'], 'timed_out')
            self.assertEqual(result['events'][1]['client_outcome'], 'acknowledged')
            self.assertEqual(sum(e.get('transport_outcome') == 'response_stalled'
                                 for e in result['events']), 1)
            self.assertEqual(result['events'][1]['committed_writes'], 1)

    def test_timeout_misreported_as_success_cannot_pass(self):
        original = transport._request
        def broken(*args, **kwargs):
            result = original(*args, **kwargs)
            return 'acknowledged' if result == 'timed_out' else result
        with patch.object(transport, '_request', side_effect=broken):
            for name in ('stalled-before-upload-commit', 'stalled-after-upload-commit'):
                result = transport.scenario(name)
                self.assertEqual(result['state'], 'FAIL')
                self.assertEqual(result['cleanup'], 'complete')

    def test_before_commit_stall_catches_unexpected_write(self):
        original = transport._relay
        @contextmanager
        def broken(*args):
            with original(*args) as server:
                server.drop_before_commit = False
                yield server
        with patch.object(transport, '_relay', broken):
            result = transport.scenario('stalled-before-upload-commit')
        self.assertEqual(result['state'], 'FAIL')
        self.assertEqual(result['events'][0]['committed_writes'], 1)

    def test_stall_cleanup_releases_handler_even_after_client_exception(self):
        captured = []
        original = transport._request
        def interrupted(server, operation, **kwargs):
            result = original(server, operation, **kwargs)
            if kwargs.get('await_stall'):
                captured.append(server)
                raise RuntimeError('PRIVATE_EXCEPTION')
            return result
        with patch.object(transport, '_request', side_effect=interrupted):
            result = transport.scenario('stalled-after-upload-commit')
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertTrue(captured[0].release_stall.is_set())
        self.assertEqual(captured[0].socket.fileno(), -1)
        self.assertNotIn('PRIVATE_EXCEPTION', json.dumps(result))

    def test_fault_not_reached_is_blocked(self):
        original = transport._relay
        @contextmanager
        def no_stall(*args):
            with original(*args) as server:
                server.stall_response = False
                yield server
        with patch.object(transport, '_relay', no_stall):
            result = transport.scenario('stalled-after-upload-commit')
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertEqual(result['reason'], 'execution_incomplete')


if __name__ == '__main__':
    unittest.main()
