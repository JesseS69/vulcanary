import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulcanary import apk_signatures as sig

CERT = 'a'*64


def verified(cert=CERT, warnings=0):
    lines=['Verifies']
    for version in ('v1','v2','v3','v3.1','v4'):
        lines.append(f"Verified using {version} scheme (Synthetic Scheme): {'true' if version=='v3' else 'false'}")
    lines+=['Verified for SourceStamp: true','Number of signers: 1',
            'Signer #1 certificate DN: CN=PRIVATE_NAME',f'Signer #1 certificate SHA-256 digest: {cert}',
            'Source Stamp Signer certificate SHA-256 digest: '+'b'*64]
    lines+=['WARNING: PRIVATE_MEMBER_NAME']*warnings
    return ('\n'.join(lines)+'\n').encode()


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.apk=self.root/'private-name.apk';self.java=self.root/'java.exe';self.jar=self.root/'apksigner.jar'
        for p in (self.apk,self.java,self.jar):p.write_bytes(b'synthetic '+p.suffix.encode())
        self.pins=[hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.apk,self.java,self.jar)]

    def tearDown(self):self.temp.cleanup()

    def run_check(self, output=None, code=0, forced=None, expected=CERT):
        replies=[(0,b'0.9\n',None),(code,verified() if output is None else output,forced)]
        with patch.object(sig.process,'run_worker',side_effect=replies) as worker:
            report=sig.verify(self.apk,self.pins[0],self.java,self.pins[1],self.jar,self.pins[2],
                              android_api=36,expected_cert_sha256=expected,authorized=True)
        return report,worker

    def test_pinned_tools_fixed_arguments_and_known_signer(self):
        report,worker=self.run_check()
        self.assertEqual(report['state'],'PASS');self.assertEqual(report['cleanup'],'complete')
        self.assertFalse(report['application_executed']);self.assertEqual(report['policy_effect'],'none')
        command=worker.call_args_list[1].args[0]
        self.assertEqual(command[0],str(self.java))
        self.assertEqual(command[-9:],['verify','--verbose','--print-certs','--min-sdk-version','36',
                                      '--max-sdk-version','36','--in',command[-1]])
        self.assertIn('--min-sdk-version',command);self.assertEqual(command[command.index('--min-sdk-version')+1],'36')
        self.assertEqual(command[command.index('--max-sdk-version')+1],'36')
        self.assertEqual(Path(command[-1]).name,'artifact.apk')
        self.assertNotIn(str(self.apk),command)
        self.assertFalse(Path(command[-1]).exists())

    def test_expected_signer_missing_wrong_and_source_stamp_not_substituted(self):
        report,_=self.run_check(expected=None)
        self.assertEqual(report['state'],'BLOCKED');self.assertEqual(report['checks'][0]['state'],'PASS')
        report,_=self.run_check(expected='b'*64)
        self.assertEqual(report['state'],'FAIL');self.assertEqual(report['signer_cert_sha256'],CERT)
        self.assertEqual(report['checks'][1]['basis'],'operator_expectation_mismatch')

    def test_warnings_do_not_mean_invalid_signature_or_disappear(self):
        report,_=self.run_check(verified(warnings=2))
        self.assertEqual(report['state'],'BLOCKED');self.assertEqual(report['checks'][0]['state'],'PASS')
        self.assertEqual(report['warning_count'],2);self.assertEqual(report['checks'][2]['state'],'BLOCKED')
        self.assertNotIn('PRIVATE_MEMBER_NAME',json.dumps(report))

    def test_forced_stop_overrides_even_successful_output_and_zero_exit(self):
        for reason in ('timeout','output_limit'):
            report,_=self.run_check(forced=reason)
            self.assertEqual(report['state'],'BLOCKED');self.assertEqual(report['reason'],'worker_limit_reached')
            self.assertIsNone(report['signer_cert_sha256'])

    def test_rejection_is_visible_and_crashes_are_not_invalid_signatures(self):
        report,_=self.run_check(b'DOES NOT VERIFY\nPRIVATE_FILE',code=1)
        self.assertEqual(report['checks'][0]['state'],'FAIL');self.assertIsNone(report['signer_cert_sha256'])
        report,_=self.run_check(b'PRIVATE_CRASH',code=1)
        self.assertEqual(report['checks'][0]['state'],'BLOCKED')
        self.assertNotIn('PRIVATE',json.dumps(report))

    def test_unknown_malformed_and_multisigner_outputs_block(self):
        base=verified()
        for raw in (b'',base.replace(b'Number of signers: 1',b'Number of signers: 2'),base+b'Unknown output\n',
                    base+b'Signer #1 certificate SHA-256 digest: '+CERT.encode()+b'\n',
                    base.replace(b'Verifies\n',b''),base.replace(b': true',b': false'),
                    base+b'\xff',base+b'\x00',b'x'*(sig.process.OUTPUT_LIMIT_BYTES+1)):
            report,_=self.run_check(raw)
            self.assertEqual(report['state'],'BLOCKED');self.assertIsNone(report['signer_cert_sha256'])

    def test_authorization_pins_and_relative_tool_refuse_before_execution(self):
        with patch.object(sig.process,'run_worker',side_effect=AssertionError('no launch')):
            report=sig.verify(self.apk,self.pins[0],self.java,self.pins[1],self.jar,self.pins[2],android_api=36)
            self.assertEqual(report['reason'],'authorization_required')
            for bad_java,pin in ((Path('java'),self.pins[1]),(self.java,'0'*64)):
                report=sig.verify(self.apk,self.pins[0],bad_java,pin,self.jar,self.pins[2],android_api=36,authorized=True)
                self.assertEqual(report['state'],'BLOCKED');self.assertFalse(report['attempted'])
            report=sig.verify(self.apk,'0'*64,self.java,self.pins[1],self.jar,self.pins[2],android_api=36,authorized=True)
            self.assertFalse(report['attempted'])

    def test_temporary_input_mutation_cannot_keep_pass(self):
        def worker(command,root,timeout):
            if command[-1]=='version':return 0,b'0.9\n',None
            (root/'artifact.apk').write_bytes(b'changed')
            return 0,verified(),None
        with patch.object(sig.process,'run_worker',side_effect=worker):
            report=sig.verify(self.apk,self.pins[0],self.java,self.pins[1],self.jar,self.pins[2],android_api=36,expected_cert_sha256=CERT,authorized=True)
        self.assertEqual(report['state'],'BLOCKED');self.assertIsNone(report['signer_cert_sha256'])

    def test_source_free_export_and_existing_output_refusal(self):
        report,_=self.run_check(verified(warnings=1))
        out=self.root/'report';sig.export(report,out)
        for path in out.iterdir():
            for value in ('PRIVATE_NAME','PRIVATE_MEMBER_NAME',str(self.apk),str(self.java)):
                self.assertNotIn(value,path.read_text())
        with self.assertRaises(FileExistsError):sig.export(report,out)

    def test_public_sdk_fixture_is_pinned_and_contains_no_private_key(self):
        import zipfile
        root=Path(__file__).parent/'fixtures/apk-signatures'
        metadata=json.loads((root/'provenance.json').read_text())
        path=root/'synthetic-signed.apk'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),metadata['artifact_sha256'])
        self.assertTrue(metadata['synthetic_only']);self.assertFalse(metadata['private_key_retained'])
        with zipfile.ZipFile(path) as z:
            self.assertEqual(hashlib.sha256(z.read('AndroidManifest.xml')).hexdigest(),metadata['manifest_sha256'])
            self.assertTrue(all(not name.lower().endswith(('.p12','.jks','.key','.pem')) for name in z.namelist()))

    def test_tool_version_refusal_and_input_limits(self):
        with patch.object(sig.process,'run_worker',side_effect=AssertionError('no launch')):
            for api,expected,timeout in ((37,CERT,30),(23,CERT,30),(36,'invalid',30),(36,CERT,0)):
                report=sig.verify(self.apk,self.pins[0],self.java,self.pins[1],self.jar,self.pins[2],
                                  android_api=api,expected_cert_sha256=expected,timeout=timeout,authorized=True)
                self.assertEqual(report['reason'],'scope_refused')
                self.assertFalse(report['attempted'])
        with patch.object(sig.process,'run_worker',return_value=(0,b'other-version\n',None)) as worker:
            report=sig.verify(self.apk,self.pins[0],self.java,self.pins[1],self.jar,self.pins[2],android_api=36,authorized=True)
        self.assertEqual(report['state'],'BLOCKED');self.assertEqual(worker.call_count,1)
        with patch.object(sig.process,'run_worker',side_effect=AssertionError('no launch')),patch.object(sig,'MAX_APK',1):
            report=sig.verify(self.apk,self.pins[0],self.java,self.pins[1],self.jar,self.pins[2],android_api=36,authorized=True)
        self.assertEqual(report['state'],'BLOCKED');self.assertFalse(report['attempted'])

    def test_cleanup_failure_removes_all_passing_claims(self):
        folder=self.root/'unremoved';folder.mkdir()
        class Unremoved:
            def __enter__(self):return str(folder)
            def __exit__(self,*args):raise PermissionError('PRIVATE_CLEANUP_ERROR')
        with patch.object(sig.tempfile,'TemporaryDirectory',return_value=Unremoved()):
            report,_=self.run_check()
        self.assertEqual(report['state'],'BLOCKED');self.assertEqual(report['cleanup'],'unconfirmed')
        self.assertTrue(all(r['state']=='BLOCKED' for r in report['checks']))
        self.assertIsNone(report['signer_cert_sha256'])
        self.assertNotIn('PRIVATE_CLEANUP_ERROR',json.dumps(report))


if __name__=='__main__':unittest.main()
