from pathlib import Path
from contextlib import contextmanager
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import database_tests as database


class DatabaseContractTests(unittest.TestCase):
    def test_real_database_contracts_and_repeated_races(self):
        report = database.run('a'*64, authorized=True)
        self.assertEqual(report['state'], 'PASS')
        self.assertEqual(report['counts'], {'PASS': 8, 'FAIL': 0, 'BLOCKED': 0})
        for row in report['checks']:
            self.assertEqual(row['cleanup'], 'complete')
            self.assertEqual(len(row['observations']), 5 if row['id'] == 'concurrent-receivers' else 1)
            self.assertTrue(all(value == row['expected'] for value in row['observations']))

    def test_deliberate_permission_and_atomicity_defects_are_caught(self):
        controls = [('bypass-tenant', 'cross-account-read'), ('bypass-tenant', 'cross-account-write'),
                    ('bypass-session', 'expired-session'), ('bypass-session', 'logged-out-session'),
                    ('bypass-approval', 'unapproved-claim'), ('bypass-expiry', 'expired-transfer'),
                    ('unchecked-claim', 'concurrent-receivers')]
        for defect, case in controls:
            with self.subTest(defect=defect, case=case):
                result = database.check(case, defect=defect)
                self.assertEqual(result['state'], 'FAIL')
                self.assertEqual(result['cleanup'], 'complete')
        result = database.check('concurrent-receivers', defect='unchecked-claim')
        self.assertTrue(all(value['accepted'] == 2 for value in result['observations']))

    def test_authorization_and_digest_checked_before_fixture_creation(self):
        with patch.object(database, 'Fixture', side_effect=AssertionError('must not create')):
            with self.assertRaises(ValueError):
                database.run('a'*64)
            with self.assertRaises(ValueError):
                database.run('invalid', authorized=True)

    def test_database_and_worker_errors_block_without_raw_output(self):
        with patch.object(database.Fixture, 'connect', side_effect=sqlite3.OperationalError('private-detail')):
            report = database.run('a'*64, authorized=True)
        self.assertEqual(report['state'], 'BLOCKED')
        self.assertEqual(report['counts']['BLOCKED'], 8)
        self.assertNotIn('private-detail', str(report))
        with patch.object(database.Fixture, 'claim', side_effect=sqlite3.OperationalError('locked')):
            result = database.check('concurrent-receivers')
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertEqual(result['observations'], [])

    def test_fixtures_are_owned_and_removed(self):
        paths = []
        original = database.Fixture.__init__
        def record(fixture, directory, defect=None):
            paths.append(directory)
            original(fixture, directory, defect)
        with patch.object(database.Fixture, '__init__', record):
            self.assertEqual(database.check('concurrent-receivers')['state'], 'PASS')
        self.assertEqual(len(paths), 5)
        self.assertTrue(all(not path.exists() for path in paths))

    def test_empty_execution_and_cleanup_failure_never_pass(self):
        with patch.object(database, 'RACE_REPETITIONS', 0):
            self.assertEqual(database.check('concurrent-receivers')['state'], 'BLOCKED')
        original = database.tempfile.TemporaryDirectory
        @contextmanager
        def failed_cleanup(*args, **kwargs):
            with original(*args, **kwargs) as directory:
                yield directory
            raise OSError('cleanup failed')
        with patch.object(database.tempfile, 'TemporaryDirectory', failed_cleanup):
            result = database.check('cross-account-read')
        self.assertEqual(result['state'], 'BLOCKED')
        self.assertEqual(result['cleanup'], 'unconfirmed')
        self.assertEqual(len(result['observations']), 1)

    def test_cli_export_and_overwrite_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'review'
            args = ['--authorize-disposable-database', '--manifest-sha256', 'a'*64, '--output', str(output)]
            self.assertEqual(database.main(args), 0)
            for path in output.iterdir():
                self.assertNotIn(directory, path.read_text())
                self.assertNotIn('receiver-a', path.read_text())
            with patch.object(database, 'run', side_effect=AssertionError('must not run')):
                self.assertEqual(database.main(args), 2)


if __name__ == '__main__':
    unittest.main()
