"""Run bundled loopback, database and storage contracts, never candidate code."""
import hashlib
import json
from pathlib import Path
import re
import uuid

from . import database_tests, storage_tests, transport_tests
from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

ADAPTERS = (('transport', transport_tests), ('database', database_tests), ('storage', storage_tests))


def run(manifest_sha256, output, *, authorized=False):
    if not authorized or not isinstance(manifest_sha256, str) or not re.fullmatch('[a-f0-9]{64}', manifest_sha256):
        raise ValueError('authorization_or_identity_required')
    # Reserve a new result directory before starting any fixture or listener.
    output.mkdir(exist_ok=False)
    rows = []
    for name, adapter in ADAPTERS:
        row = dict(id=name, state='BLOCKED', reason='execution_incomplete', report=None)
        try:
            result = adapter.run(manifest_sha256, authorized=True)
            adapter.export(result, output/name)
            state = result['state'] if result.get('state') in ('PASS','FAIL','BLOCKED') else 'BLOCKED'
            row.update(state=state, reason='adapter_report', report=name+'/report.json')
        except (OSError, ValueError, RuntimeError):
            # Keep evidence from other adapters; no raw exception data in the package.
            pass
        rows.append(row)
    state = ('BLOCKED' if not rows or any(r['state']=='BLOCKED' for r in rows)
             else 'FAIL' if any(r['state']=='FAIL' for r in rows) else 'PASS')
    report = dict(schema='vulcanary.isolated-lab.v1', producer_version=__version__, run_id=str(uuid.uuid4()),
                  manifest_sha256=manifest_sha256, state=state, candidate_state='NOT_RUN',
                  policy_effect='none', independent_certification=False, adapters=rows,
                  implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  evidence_method='bundled-contracts-only',
                  limitations=['PASS describes bundled infrastructure only, never the candidate application.',
                               'No target endpoint, credentials, source commands, device or private key input is accepted.',
                               'The loopback adapter opens only its own 127.0.0.1 listener; this is not an OS sandbox.',
                               'Production backend, native key store, browser storage and iOS execution remain untested.'])
    write_new(output/'report.json', report)
    with (output/'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('# Isolated reference lab\n\nInfrastructure: '+state+'\n\nCandidate: NOT_RUN\n\n')
        for row in rows:
            stream.write('- '+row['id']+': '+row['state']+' ('+row['reason']+')\n')
        stream.write('\n'+'\n'.join('- '+value for value in report['limitations'])+'\n')
        stream.write('\nChecksums are unsigned integrity records, not certification.\n')
    # Fixed files emitted by bundled exporters, not arbitrary user filesystem input.
    files = [output/'report.json', output/'reviewer.md']
    for name, _ in ADAPTERS:
        files += [output/name/leaf for leaf in ('report.json','reviewer.md','checksums.json')
                  if (output/name/leaf).is_file()]
    write_new(output/'checksums.json', {file.relative_to(output).as_posix():hashlib.sha256(file.read_bytes()).hexdigest()
                                      for file in files})
    return report


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--authorize-owned-synthetic-lab', action='store_true')
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        report = run(args.manifest_sha256, args.output, authorized=args.authorize_owned_synthetic_lab)
        print(json.dumps({'state':report['state'],'candidate_state':report['candidate_state']}))
        return 0 if report['state']=='PASS' else 1 if report['state']=='FAIL' else 2
    except (OSError, ValueError, TypeError):
        print('Lab blocked. Authorize owned synthetic fixtures, supply a manifest digest and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
