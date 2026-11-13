import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from vulcanary import isolated_lab as lab, storage_tests


class IsolatedLabTests(unittest.TestCase):
    def test_real_storage_export_and_candidate_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'run'
            with patch.object(lab,'ADAPTERS',(('storage',storage_tests),)):
                report = lab.run('a'*64,output,authorized=True)
            self.assertEqual(report['state'],'PASS')
            self.assertEqual(report['candidate_state'],'NOT_RUN')
            hashes = json.loads((output/'checksums.json').read_text())
            self.assertEqual(len(hashes),5)
            for name,digest in hashes.items():
                self.assertEqual(hashlib.sha256((output/name).read_bytes()).hexdigest(),digest)
            self.assertNotIn(directory,(output/'report.json').read_text())

    def test_adapter_failure_does_not_skip_later_adapters(self):
        broken = Mock()
        broken.run.side_effect = OSError('PRIVATE-DETAIL')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'run'
            with patch.object(lab,'ADAPTERS',(('broken',broken),('storage',storage_tests))):
                report = lab.run('a'*64,output,authorized=True)
            self.assertEqual([r['state'] for r in report['adapters']],['BLOCKED','PASS'])
            self.assertEqual(report['state'],'BLOCKED')
            self.assertNotIn('PRIVATE-DETAIL',(output/'report.json').read_text())

    def test_no_authorization_or_existing_output_never_executes(self):
        adapter = Mock()
        with tempfile.TemporaryDirectory() as directory, patch.object(lab,'ADAPTERS',(('fake',adapter),)):
            with self.assertRaises(ValueError):
                lab.run('a'*64,Path(directory)/'new')
            with self.assertRaises(OSError):
                lab.run('a'*64,Path(directory),authorized=True)
        adapter.run.assert_not_called()

    def test_empty_or_unknown_state_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(lab,'ADAPTERS',()):
                self.assertEqual(lab.run('a'*64,Path(directory)/'empty',authorized=True)['state'],'BLOCKED')
            adapter = Mock()
            adapter.run.return_value = {'state':'NOT_RUN'}
            with patch.object(lab,'ADAPTERS',(('fake',adapter),)):
                self.assertEqual(lab.run('a'*64,Path(directory)/'unknown',authorized=True)['state'],'BLOCKED')


if __name__ == '__main__':
    unittest.main()
