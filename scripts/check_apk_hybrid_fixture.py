"""Explicit offline integration controls using pinned public AOSP synthetic APKs."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from vulcanary import apk_hybrid_signatures as sig


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('java','jar'): parser.add_argument('--'+name,type=Path,required=True)
    for name in ('java-sha256','jar-sha256'): parser.add_argument('--'+name,required=True)
    parser.add_argument('--authorize-trusted-verifier',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]/'tests/fixtures/apk-hybrid-signatures'
    manifest=json.loads((root/'provenance.json').read_text())
    positive=manifest['artifacts'][0];certs=positive['synthetic_certificates']
    def check(path,pin,expected=None):
        expected=certs if expected is None else expected
        return sig.verify(path,pin,args.java,args.java_sha256,args.jar,args.jar_sha256,android_api=37,
                          expected_classical_sha256=expected['classical'],expected_pqc_sha256=expected['pqc'],
                          authorized=args.authorize_trusted_verifier)
    good=check(root/positive['file'],positive['sha256'])
    wrong=check(root/positive['file'],positive['sha256'],{'classical':certs['pqc'],'pqc':certs['classical']})
    controls={'valid_hybrid_verified':good['checks'][0]['state']=='PASS' and good['schemes']['v3.2'],
              'synthetic_role_pins_match':good['checks'][1]['state']=='PASS',
              'swapped_roles_fail':wrong['checks'][1]['state']=='FAIL',
              'warnings_not_suppressed':good['warning_count']==positive['expected_warning_count'] and good['checks'][2]['state']=='BLOCKED'}
    for fixture in manifest['artifacts'][1:]:
        report=check(root/fixture['file'],fixture['sha256'])
        controls[fixture['file']]=report['checks'][0]['state']=='FAIL'
    data=(root/positive['file']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=positive['sha256']:raise ValueError('fixture changed')
    with tempfile.TemporaryDirectory(prefix='vulcanary-hybrid-control-') as folder:
        for i,offset in enumerate(positive['hybrid_signature_mutation_offsets']):
            changed=bytearray(data);changed[offset]^=1
            path=Path(folder)/f'control-{i}.apk';path.write_bytes(changed)
            report=check(path,hashlib.sha256(changed).hexdigest())
            controls[f'hybrid_signature_{i}_tamper_rejected']=report['checks'][0]['state']=='FAIL'
    print(json.dumps(controls,sort_keys=True))
    return 0 if all(controls.values()) else 2


if __name__=='__main__':raise SystemExit(main())
