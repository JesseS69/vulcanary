from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import storage_tests as storage


class StorageTests(unittest.TestCase):
    def test_real_storage_and_every_mutation_control(self):
        self.assertEqual(set(storage.CONTROLS), set(storage.CASES))
        report = storage.run('a'*64, authorized=True)
        self.assertEqual(report['counts'], {'PASS':7,'FAIL':0,'BLOCKED':0})
        self.assertEqual(report['state'], 'PASS')
        for row in report['checks']:
            self.assertEqual(row['observed'], row['expected'])
            self.assertEqual(row['cleanup'], 'complete')
        for case, defect in storage.CONTROLS.items():
            with self.subTest(case=case):
                row = storage.check(case, defect=defect)
                self.assertEqual(row['state'], 'FAIL')
                self.assertEqual(row['cleanup'], 'complete')

    def test_capacity_is_actual_sqlite_full_and_retry_recovers(self):
        row = storage.check('sqlite-capacity')
        self.assertTrue(row['observed']['capacity_error'])
        self.assertTrue(row['observed']['prior_state_preserved'])
        self.assertTrue(row['observed']['retry_state_verified'])

    def test_fault_activation_is_required(self):
        with patch.object(storage.Store, 'install', return_value={'fault_reached':False}):
            self.assertEqual(storage.check('partial-install')['state'], 'BLOCKED')

    def test_failed_setup_blocks_and_redacts(self):
        with patch.object(storage.Store, 'connect', side_effect=sqlite3.OperationalError('PRIVATE-DETAIL')):
            report = storage.run('a'*64, authorized=True)
        self.assertEqual(report['counts']['BLOCKED'], 7)
        self.assertNotIn('PRIVATE-DETAIL', json.dumps(report))

    def test_authorization_before_fixture_and_existing_output_before_run(self):
        with patch.object(storage, 'Store', side_effect=AssertionError('must not create')):
            for digest, authorized in [('a'*64,False),('invalid',True),(None,True)]:
                with self.assertRaises(ValueError):
                    storage.run(digest, authorized=authorized)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(storage, 'run', side_effect=AssertionError('must not run')):
                self.assertEqual(storage.main(['--authorize-disposable-storage','--manifest-sha256',
                                              'a'*64,'--output',directory]),2)

    def test_cleanup_is_confined_and_failure_blocks(self):
        paths = []
        original = storage.Store.__init__
        def record(store, directory):
            paths.append(directory)
            original(store,directory)
        with patch.object(storage.Store,'__init__',record):
            self.assertEqual(storage.check('partial-install')['state'],'PASS')
        self.assertTrue(paths)
        self.assertTrue(all(not p.exists() for p in paths))
        temporary = storage.tempfile.TemporaryDirectory
        @contextmanager
        def failed_cleanup(*args,**kwargs):
            with temporary(*args,**kwargs) as directory:
                yield directory
            raise OSError('PRIVATE-PATH')
        with patch.object(storage.tempfile,'TemporaryDirectory',failed_cleanup):
            row = storage.check('partial-install')
        self.assertEqual(row['state'],'BLOCKED')
        self.assertEqual(row['cleanup'],'unconfirmed')

    def test_unknown_and_empty_execution_cannot_pass(self):
        with patch.object(storage,'CASES',()):
            self.assertEqual(storage.run('a'*64,authorized=True)['state'],'BLOCKED')
        with patch.object(storage,'check',return_value={'state':'NOT_RUN'}):
            self.assertEqual(storage.run('a'*64,authorized=True)['state'],'BLOCKED')
        with self.assertRaises(ValueError):
            storage.check('not-a-case')

    def test_export_sanitized_and_cli_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)/'new'
            args = ['--authorize-disposable-storage','--manifest-sha256','a'*64,'--output',str(out)]
            self.assertEqual(storage.main(args),0)
            for file in out.iterdir():
                text = file.read_text()
                for private in (directory,'synthetic-one','synthetic-two','wrong-synthetic-value','fixture.sqlite'):
                    self.assertNotIn(private,text)
            with patch.object(storage,'check',return_value={'id':'x','state':'FAIL','reason':'assertion_failed',
                     'cleanup':'complete','expected':{},'observed':{}}):
                args[-1] = str(Path(directory)/'fail')
                self.assertEqual(storage.main(args),1)


if __name__ == '__main__':
    unittest.main()
