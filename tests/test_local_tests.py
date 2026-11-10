import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from vulcanary import local_tests as runner
from vulcanary._test_process import run_worker


class LocalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.python = Path(sys.executable).resolve()
        self.pin = hashlib.sha256(self.python.read_bytes()).hexdigest()
        self.version = '.'.join(map(str, sys.version_info[:3]))
        self.spec = self.root / 'spec.json'
        self.spec.write_text(json.dumps({'cases': [{'input_hex': '616263',
            'expected_sha256': hashlib.sha256(b'abc').hexdigest()}]}))

    def execute(self, **kwargs):
        return runner.execute(self.spec, self.python, self.pin, self.version,
                              authorized=True, **kwargs)

    def worker(self, source, timeout=2, **kwargs):
        path = self.root / 'worker.py'
        path.write_text('import sys\nsys.stdin.buffer.readline(4)\n' + source)
        return run_worker([str(self.python), '-I', '-S', str(path)], self.root, timeout, **kwargs)

    def test_real_pass_fail_and_no_source_in_report(self):
        good = self.execute()
        self.assertEqual(good['state'], 'PASS')
        self.assertEqual(good['observed']['run'], 1)
        self.assertEqual(good['cleanup'], 'complete')
        self.assertTrue(good['executed'])
        self.spec.write_text(json.dumps({'cases': [{'input_hex': '616263', 'expected_sha256': '0' * 64}]}))
        bad = self.execute()
        self.assertEqual(bad['state'], 'FAIL')
        self.assertEqual(bad['observed']['failures'], 1)
        self.assertEqual(bad['observed']['failed_cases'], [1])
        self.assertNotIn('616263', json.dumps(bad))
        self.assertNotIn(str(self.root), json.dumps(bad))
        self.assertEqual(good['target_sha256'], bad['target_sha256'])
        self.assertNotEqual(good['plan_sha256'], bad['plan_sha256'])

    def test_authorization_and_tool_pin_fail_before_launch(self):
        with patch.object(runner, 'run_worker', side_effect=AssertionError('must not launch')):
            denied = runner.execute(self.spec, self.python, self.pin, self.version)
            self.assertEqual(denied['reason'], 'authorization_required')
            for path, pin in ((Path('python'), self.pin), (self.root/'missing', self.pin), (self.python, '0'*64)):
                result = runner.execute(self.spec, path, pin, self.version, authorized=True)
                self.assertEqual(result['state'], 'BLOCKED')
                self.assertFalse(result['attempted'])

    def test_invalid_vectors_scope_and_empty_suite_never_launch(self):
        for document in ({'cases': []}, {'cases': [], 'endpoint': 'https://example.invalid'},
                         {'cases': [{'input_hex': '__import__("os")', 'expected_sha256': '0'*64}]},
                         {'cases': [{'input_hex': 'a'*8194, 'expected_sha256': '0'*64}]}):
            self.spec.write_text(json.dumps(document))
            with patch.object(runner, 'run_worker', side_effect=AssertionError('must not launch')):
                self.assertEqual(self.execute()['state'], 'BLOCKED')

    def test_result_protocol_cannot_turn_incomplete_tests_into_pass(self):
        base = {'protocol': 1, 'python': list(sys.version_info[:3]), 'run': 1,
                'failures': 0, 'errors': 0, 'skipped': 0, 'failed_cases': []}
        variants = [{'run': 0}, {'run': True}, {'skipped': 1}, {'errors': 1},
                    {'failures': 2}, {'python': [0, 0, 0]}, {'private': 'SYNTHETIC-SECRET'}]
        for changes in variants:
            with patch.object(runner, 'run_worker', return_value=(0, json.dumps(base | changes).encode(), None)):
                report = self.execute()
                self.assertEqual(report['state'], 'BLOCKED')
                self.assertIsNone(report['observed'])
                self.assertNotIn('SYNTHETIC-SECRET', json.dumps(report))

    def test_crash_raw_output_timeout_and_cleanup_failure_never_pass(self):
        for result in ((1, b'SYNTHETIC-SECRET', None), (0, b'SYNTHETIC-SECRET', None),
                       (-1, b'SYNTHETIC-SECRET', 'timeout'), (-1, b'', 'output_limit')):
            with patch.object(runner, 'run_worker', return_value=result):
                report = self.execute()
                self.assertEqual(report['state'], 'BLOCKED')
                self.assertNotIn('SYNTHETIC-SECRET', json.dumps(report))
        with patch.object(runner, 'run_worker', side_effect=OSError('SYNTHETIC-SECRET')):
            report = self.execute()
            self.assertEqual(report['cleanup'], 'unconfirmed')
            self.assertEqual(report['state'], 'BLOCKED')

    def test_actual_timeout_and_output_flood_are_bounded(self):
        started = time.monotonic()
        self.assertEqual(self.worker('import time\ntime.sleep(30)\n', timeout=.2)[2], 'timeout')
        self.assertLess(time.monotonic() - started, 6)
        code, output, reason = self.worker("while True: print('x'*1024, flush=True)\n", output_limit=2048)
        self.assertEqual(reason, 'output_limit')
        self.assertLessEqual(len(output), 2048)

    def test_real_worker_crash_is_not_a_completed_assertion(self):
        code, output, reason = self.worker("raise RuntimeError('SYNTHETIC-SECRET')\n")
        self.assertNotEqual(code, 0)
        with patch.object(runner, 'run_worker', return_value=(code, output, reason)):
            report = self.execute()
        self.assertEqual(report['reason'], 'worker_crash')
        self.assertFalse(report['executed'])
        self.assertNotIn('SYNTHETIC-SECRET', json.dumps(report))

    def test_actual_process_tree_stops(self):
        marker = self.root / 'child-lived'
        child = "import time; from pathlib import Path; time.sleep(1); Path('child-lived').write_text('bad')"
        source = ('import subprocess, time\ntry:\n'
                  '    subprocess.Popen([sys.executable, "-I", "-S", "-c", ' + repr(child) + '])\n'
                  'except OSError:\n    pass\ntime.sleep(30)\n')
        self.assertEqual(self.worker(source, timeout=.4)[2], 'timeout')
        time.sleep(1.1)
        self.assertFalse(marker.exists())

    def test_environment_is_minimized_and_cwd_is_disposable(self):
        with patch.dict(os.environ, {'VULCANARY_TEST_SECRET': 'SYNTHETIC-SECRET', 'PYTHONPATH': 'hostile'}):
            code, output, reason = self.worker('import os, json\nprint(json.dumps({"secret": os.getenv("VULCANARY_TEST_SECRET"), "pythonpath": os.getenv("PYTHONPATH"), "cwd": os.getcwd(), "home": os.getenv("HOME")}))\n')
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertIsNone(result['secret'])
        self.assertIsNone(result['pythonpath'])
        self.assertEqual(Path(result['cwd']), self.root)
        self.assertEqual(Path(result['home']), self.root)

    def test_children_are_stopped_after_success_too(self):
        source = ('import subprocess\nsubprocess.Popen([sys.executable, "-I", "-S", "-c", '
                  '"import time; from pathlib import Path; time.sleep(1); Path(\'late-write\').write_text(\'bad\')"])\n'
                  'print("complete")\n')
        code, output, reason = self.worker(source)
        self.assertEqual(code, 0)
        self.assertIsNone(reason)
        time.sleep(1.1)
        self.assertFalse((self.root / 'late-write').exists())

    def test_invalid_timeout_never_launches(self):
        for timeout in (0, 31, float('inf'), float('nan'), True):
            with patch.object(runner, 'run_worker', side_effect=AssertionError('must not launch')):
                self.assertEqual(self.execute(timeout=timeout)['reason'], 'invalid_timeout')

    @unittest.skipUnless(os.name == 'nt', 'Windows suspended launch invariant')
    def test_windows_job_failure_cannot_execute_even_bootstrap_code(self):
        from vulcanary import _test_process
        path = self.root / 'bootstrap.py'
        path.write_text("from pathlib import Path\nPath('escaped').write_text('bad')\n")
        with patch.object(_test_process, 'WindowsJob', side_effect=OSError('job unavailable')):
            with self.assertRaises(OSError):
                run_worker([str(self.python), '-I', '-S', str(path)], self.root, 2)
        self.assertFalse((self.root / 'escaped').exists())

    def test_export_refuses_overwrite_and_is_source_free(self):
        destination = self.root / 'export'
        args = ['--spec', str(self.spec), '--python', str(self.python), '--python-sha256', self.pin,
                '--python-version', self.version, '--authorize-trusted-local-tests', '--output', str(destination)]
        self.assertEqual(runner.main(args), 0)
        with patch.object(runner, 'execute', side_effect=AssertionError('must not run')):
            self.assertEqual(runner.main(args), 2)
        for path in destination.iterdir():
            self.assertNotIn('616263', path.read_text())
            self.assertNotIn(str(self.root), path.read_text())


if __name__ == '__main__':
    unittest.main()
