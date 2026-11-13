"""Explicit offline SDK integration check; never downloads tools or reads a device."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import zipfile

from vulcanary import apk_signatures as sig


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java',type=Path,required=True)
    parser.add_argument('--java-sha256',required=True)
    parser.add_argument('--jar',type=Path,required=True)
    parser.add_argument('--jar-sha256',required=True)
    parser.add_argument('--authorize-trusted-verifier',action='store_true')
    args=parser.parse_args()
    fixture=Path(__file__).resolve().parents[1]/'tests/fixtures/apk-signatures'
    expected=json.loads((fixture/'provenance.json').read_text())
    def verify(path,pin,cert):
        return sig.verify(path,pin,args.java,args.java_sha256,args.jar,args.jar_sha256,android_api=36,
                          expected_cert_sha256=cert,authorized=args.authorize_trusted_verifier)
    good=verify(fixture/'synthetic-signed.apk',expected['artifact_sha256'],expected['signer_cert_sha256'])
    wrong=verify(fixture/'synthetic-signed.apk',expected['artifact_sha256'],'0'*64)
    with tempfile.TemporaryDirectory(prefix='vulcanary-signature-control-') as folder:
        path=Path(folder)/'mutated.apk';shutil.copyfile(fixture/'synthetic-signed.apk',path)
        with zipfile.ZipFile(path) as z:
            item=z.getinfo('assets/synthetic.txt')
        with path.open('r+b') as f:
            f.seek(item.header_offset);header=f.read(30)
            name,extra=struct.unpack_from('<HH',header,26)
            f.seek(item.header_offset+30+name+extra)
            byte=f.read(1);f.seek(-1,1);f.write(bytes([byte[0]^1]))
        bad=verify(path,hashlib.sha256(path.read_bytes()).hexdigest(),expected['signer_cert_sha256'])
    controls={'signed_fixture_passes':good['state']=='PASS',
              'wrong_signer_fails':wrong['checks'][1]['state']=='FAIL',
              'tampered_payload_rejected':bad['checks'][0]['state']=='FAIL'}
    print(json.dumps(controls,sort_keys=True))
    return 0 if all(controls.values()) else 2


if __name__=='__main__':raise SystemExit(main())
