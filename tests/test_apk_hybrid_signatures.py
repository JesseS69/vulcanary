import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import apk_hybrid_signatures as sig

C, P, F, S = ('a'*64, 'b'*64, 'c'*64, 'd'*64)


def verified(warnings=0):
    lines = ['Verifies', 'Number of signers: 1']
    for scheme in ('v1', 'v2', 'v3', 'v3.1', 'v3.2', 'v4'):
        lines.append(f"Verified using {scheme} scheme (Synthetic): {'true' if scheme in ('v3', 'v3.2') else 'false'}")
    for label, cert in (('V3.2 Hybrid Classical Signer', C), ('V3.2 Hybrid PQC Signer', P)):
        prefix = label + ': (minSdkVersion=37, maxSdkVersion=2147483647) '
        lines += [prefix+'certificate DN: PRIVATE_NAME', prefix+'certificate SHA-256 digest: '+cert]
    lines += ['V3.0 Signer: certificate SHA-256 digest: '+F,
              'Source Stamp Signer: certificate SHA-256 digest: '+S]
    lines += ['WARNING: PRIVATE_DIAGNOSTIC']*warnings
    return ('\n'.join(lines)+'\n').encode()


class HybridTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.paths = [self.root/name for name in ('private.apk','java.exe','verifier.jar')]
        for path in self.paths: path.write_bytes(b'synthetic')
        self.args = [item for path in self.paths for item in (path, hashlib.sha256(path.read_bytes()).hexdigest())]

    def tearDown(self): self.temp.cleanup()

    def run_check(self, raw=None, expected=(C,P), code=0, forced=None):
        with patch.object(sig.process, 'run_worker', side_effect=[(0,b'0.9\n',None), (code,verified() if raw is None else raw,forced)]) as worker:
            report = sig.verify(*self.args, android_api=37, expected_classical_sha256=expected[0],
                                expected_pqc_sha256=expected[1], authorized=True)
        return report,worker

    def test_role_specific_expectations_and_fixed_api(self):
        report,worker = self.run_check()
        self.assertEqual(report['state'],'PASS')
        self.assertEqual(report['signers'],{'classical':C,'pqc':P,'fallback':F})
        command = worker.call_args_list[1].args[0]
        self.assertEqual(command[command.index('--min-sdk-version')+1],'37')
        self.assertEqual(command[command.index('--max-sdk-version')+1],'37')
        self.assertFalse(Path(command[-1]).exists())

    def test_missing_expectations_never_pass(self):
        for expected in ((None,None),(C,None),(None,P)):
            report,_ = self.run_check(expected=expected)
            self.assertEqual(report['state'],'BLOCKED')
            self.assertEqual(report['checks'][0]['state'],'PASS')

    def test_swapped_fallback_and_stamp_never_substitute(self):
        for expected in ((P,C),(F,P),(C,F),(S,P),(C,S),(F,None)):
            report,_=self.run_check(expected=expected)
            self.assertEqual(report['checks'][1]['state'],'FAIL')

    def test_duplicate_expectations_refuse_before_launch(self):
        with patch.object(sig.process,'run_worker',side_effect=AssertionError('no launch')):
            r=sig.verify(*self.args,android_api=37,expected_classical_sha256=C,expected_pqc_sha256=C,authorized=True)
        self.assertFalse(r['attempted'])

    def test_warnings_remain_blocked_and_private(self):
        report,_=self.run_check(verified(2))
        self.assertEqual(report['state'],'BLOCKED')
        self.assertEqual(report['warning_count'],2)
        self.assertEqual(report['checks'][0]['state'],'PASS')
        self.assertNotIn('PRIVATE',json.dumps(report))

    def test_missing_duplicate_unknown_roles_and_legacy_output_refused(self):
        base=verified()
        mutants=[base.replace(P.encode(),C.encode()), base.replace(b'Hybrid PQC',b'Hybrid Unknown'),
                 base+b'V3.0 Signer: certificate SHA-256 digest: '+F.encode()+b'\n',
                 base.replace(b'Number of signers: 1',b'Number of signers: 2'),
                 base.replace(b'v3.2 scheme (Synthetic): true',b'v3.2 scheme (Synthetic): false'),
                 base.replace(b'Verifies\n',b''),base+b'unknown\n',base+b'\x00',base+b'\xff',
                 base.replace(b'V3.0 Signer:',b'Signer #1'),base.replace(b'certificate SHA-256 digest: '+P.encode(),b'certificate SHA-1 digest: x')]
        for raw in mutants:
            with self.subTest(raw=raw[:20]):
                report,_=self.run_check(raw)
                self.assertEqual(report['state'],'BLOCKED')
                self.assertIsNone(report['signers'])

    def test_range_mismatch_and_outside_api_refused(self):
        for raw in (verified().replace(b'maxSdkVersion=2147483647',b'maxSdkVersion=36'),
                    verified().replace(b'minSdkVersion=37',b'minSdkVersion=38'),
                    verified().replace(b'minSdkVersion=37',b'minSdkVersion=36',1)):
            report,_=self.run_check(raw)
            self.assertIsNone(report['signers'])

    def test_forced_stop_and_rejection(self):
        for forced in ('timeout','output_limit'):
            report,_=self.run_check(forced=forced)
            self.assertEqual(report['state'],'BLOCKED')
            self.assertIsNone(report['signers'])
        report,_=self.run_check(b'DOES NOT VERIFY\n',code=1)
        self.assertEqual(report['checks'][0]['state'],'FAIL')

    def test_authorization_and_other_api_refuse(self):
        with patch.object(sig.process,'run_worker',side_effect=AssertionError('no launch')):
            for api,authorized in ((37,False),(36,True),(38,True)):
                report=sig.verify(*self.args,android_api=api,authorized=authorized)
                self.assertFalse(report['attempted'])

    def test_bad_pin_and_mutated_snapshot_refuse(self):
        args=list(self.args);args[1]='0'*64
        with patch.object(sig.process,'run_worker',side_effect=AssertionError('no launch')):
            report=sig.verify(*args,android_api=37,authorized=True)
        self.assertFalse(report['attempted'])
        def worker(command,root,timeout):
            if command[-1]=='version': return 0,b'0.9\n',None
            (root/'artifact.apk').write_bytes(b'changed')
            return 0,verified(),None
        with patch.object(sig.process,'run_worker',side_effect=worker):
            report=sig.verify(*self.args,android_api=37,authorized=True)
        self.assertIsNone(report['signers'])
        self.assertEqual(report['state'],'BLOCKED')

    def test_cleanup_failure_clears_roles_and_passes(self):
        folder=self.root/'leftover';folder.mkdir()
        class Unremoved:
            def __enter__(self): return str(folder)
            def __exit__(self,*args): raise PermissionError('PRIVATE')
        with patch.object(sig.tempfile,'TemporaryDirectory',return_value=Unremoved()):
            report,_=self.run_check()
        self.assertIsNone(report['signers']);self.assertIsNone(report['signer_ranges'])
        self.assertTrue(all(r['state']=='BLOCKED' for r in report['checks']))

    def test_sanitized_export(self):
        report,_=self.run_check(verified(1));out=self.root/'report';sig.export(report,out)
        for p in out.iterdir():
            self.assertNotIn('PRIVATE',p.read_text())
            self.assertNotIn(str(self.root),p.read_text())

    def test_legacy_contract_still_refuses_new_output(self):
        from vulcanary.apk_signatures import parse_verified
        with self.assertRaises(ValueError): parse_verified(verified())

    def test_development_range_annotation_is_preserved_and_consistent(self):
        raw=verified().replace(b'minSdkVersion=37', b'minSdkVersion=36 (dev release=true)')
        report,_=self.run_check(raw)
        self.assertEqual(report['signer_dev_releases'],{'classical':True,'pqc':True})
        self.assertEqual(report['signer_ranges']['pqc'],[36,2147483647])
        report,_=self.run_check(raw.replace(b'dev release=true',b'dev release=false',1))
        self.assertIsNone(report['signers'])

    def test_public_upstream_fixture_bytes_and_mutation_offsets_pinned(self):
        import zipfile
        root=Path(__file__).parent/'fixtures/apk-hybrid-signatures'
        metadata=json.loads((root/'provenance.json').read_text())
        self.assertFalse(metadata['private_key_included'])
        for entry in metadata['artifacts']:
            data=(root/entry['file']).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(),entry['sha256'])
            self.assertEqual(len(data),entry['size'])
            with zipfile.ZipFile(root/entry['file']) as archive:
                self.assertTrue(all(not n.lower().endswith(('.p12','.jks','.key','.pem')) for n in archive.namelist()))
        self.assertEqual(len(metadata['artifacts'][0]['hybrid_signature_mutation_offsets']),2)



if __name__=='__main__': unittest.main()
