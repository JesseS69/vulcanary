"""Disposable SQLite install/receipt fault contracts; never application key storage."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import uuid

from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

CASES = ('write-refusal', 'partial-install', 'readback-mismatch', 'receipt-refusal',
         'lost-ack-retry', 'stale-session', 'sqlite-capacity')
CONTROLS = {case: 'false-success' for case in CASES}
CONTROLS.update({'partial-install': 'commit-partial', 'receipt-refusal': 'commit-partial',
                 'lost-ack-retry': 'duplicate-install', 'stale-session': 'ignore-session'})


class InjectedFault(Exception):
    pass


class Store:
    """Fixed synthetic records, bounded writes and one owned database per scenario."""

    def __init__(self, directory):
        self.path = directory / 'fixture.sqlite'
        with closing(self.connect()) as db, db:
            db.executescript('''
                CREATE TABLE session (id INTEGER PRIMARY KEY, epoch INTEGER);
                INSERT INTO session VALUES (1,1);
                CREATE TABLE material (id INTEGER PRIMARY KEY, value BLOB);
                INSERT INTO material VALUES (1,X'0102'),(2,X'0304');
                CREATE TABLE receipt (id INTEGER PRIMARY KEY);
                CREATE TABLE installs (id INTEGER PRIMARY KEY, count INTEGER);
                INSERT INTO installs VALUES (1,0);
                CREATE TABLE capacity_probe (value BLOB);
            ''')

    def connect(self):
        return sqlite3.connect(self.path, timeout=0.2)

    def snapshot(self):
        # Read with a fresh connection, never rely on the writer's in-memory view.
        with closing(self.connect()) as db:
            return (db.execute('SELECT * FROM material ORDER BY id').fetchall(),
                    db.execute('SELECT * FROM receipt').fetchall(),
                    db.execute('SELECT count FROM installs').fetchone()[0])

    def switch_session(self):
        with closing(self.connect()) as db, db:
            db.execute('UPDATE session SET epoch=2')

    def install(self, fault=None, defect=None):
        reached = False
        with closing(self.connect()) as db:
            if fault == 'sqlite-capacity':
                db.execute('PRAGMA max_page_count=16')
            try:
                db.execute('BEGIN IMMEDIATE')
                if db.execute('SELECT epoch FROM session WHERE id=1').fetchone()[0] != 1:
                    reached = True
                    if defect != 'ignore-session':
                        raise InjectedFault()
                if db.execute('SELECT 1 FROM receipt WHERE id=1').fetchone() and defect != 'duplicate-install':
                    db.rollback()
                    return {'acknowledged': True, 'fault_reached': reached, 'capacity_error': False}
                if fault == 'write-refusal':
                    reached = True
                    raise InjectedFault()
                db.execute('UPDATE material SET value=? WHERE id=1', (b'synthetic-one',))
                if fault == 'partial-install':
                    reached = True
                    raise InjectedFault()
                if fault == 'sqlite-capacity':
                    # A real SQLite capacity error, not a full host disk or mocked exception.
                    db.execute('INSERT INTO capacity_probe VALUES (zeroblob(131072))')
                    raise RuntimeError('capacity_fault_not_reached')
                db.execute('UPDATE material SET value=? WHERE id=2', (b'synthetic-two',))
                if fault == 'readback-mismatch':
                    db.execute('UPDATE material SET value=? WHERE id=2', (b'wrong-synthetic-value',))
                actual = db.execute('SELECT value FROM material ORDER BY id').fetchall()
                if actual != [(b'synthetic-one',), (b'synthetic-two',)]:
                    reached = True
                    raise InjectedFault()
                if fault == 'receipt-refusal':
                    reached = True
                    raise InjectedFault()
                db.execute('INSERT OR IGNORE INTO receipt VALUES (1)')
                db.execute('UPDATE installs SET count=count+1 WHERE id=1')
                db.commit()
                if fault == 'lost-ack-retry':
                    return {'acknowledged': False, 'fault_reached': True, 'capacity_error': False}
                return {'acknowledged': True, 'fault_reached': reached, 'capacity_error': False}
            except InjectedFault:
                if defect == 'commit-partial':
                    db.commit()
                else:
                    db.rollback()
                return {'acknowledged': defect == 'false-success', 'fault_reached': reached, 'capacity_error': False}
            except sqlite3.Error as error:
                db.rollback()
                if fault != 'sqlite-capacity' or getattr(error, 'sqlite_errorcode', None) != sqlite3.SQLITE_FULL:
                    raise
                return {'acknowledged': defect == 'false-success', 'fault_reached': True, 'capacity_error': True}


def check(case, *, defect=None):
    if case not in CASES or defect not in (None, *set(CONTROLS.values())):
        raise ValueError('unsupported_case_or_control')
    row = dict(id=case, state='BLOCKED', reason='execution_incomplete', cleanup='unconfirmed',
               expected=None, observed=None)
    try:
        with tempfile.TemporaryDirectory(prefix='vulcanary-storage-') as directory:
            store = Store(Path(directory))
            before = store.snapshot()
            if case == 'stale-session':
                store.switch_session()
            result = store.install(case, defect)
            if not result['fault_reached']:
                raise RuntimeError('fault_not_reached')
            after = store.snapshot()
            if case == 'lost-ack-retry':
                expected = {'fault_reached': True, 'first_acknowledged': False,
                            'committed_before_retry': True, 'retry_acknowledged': True,
                            'retry_unchanged': True, 'install_count': 1}
                retry = Store.__new__(Store)
                retry.path = store.path  # Fresh object/connection; no reconstruction of fixture state.
                retried = retry.install(defect=defect)
                final = retry.snapshot()
                observed = dict(fault_reached=True, first_acknowledged=result['acknowledged'],
                                committed_before_retry=after == ([(1,b'synthetic-one'),(2,b'synthetic-two')],[(1,)],1),
                                retry_acknowledged=retried['acknowledged'], retry_unchanged=final == after,
                                install_count=final[2])
            else:
                expected = {'fault_reached': True, 'acknowledged': False, 'prior_state_preserved': True,
                            'retry_acknowledged': case != 'stale-session',
                            'retry_state_verified': True,
                            'capacity_error': case == 'sqlite-capacity'}
                # Capacity limit is connection-local; retry reconnects with ordinary capacity.
                retried = store.install()
                final = store.snapshot()
                wanted = before if case == 'stale-session' else ([(1,b'synthetic-one'),(2,b'synthetic-two')],[(1,)],1)
                observed = dict(fault_reached=True, acknowledged=result['acknowledged'],
                                prior_state_preserved=before == after,
                                retry_state_verified=final == wanted,
                                retry_acknowledged=retried['acknowledged'], capacity_error=result['capacity_error'])
            row.update(expected=expected, observed=observed)
        row.update(cleanup='complete', state='PASS' if observed == expected else 'FAIL',
                   reason='assertions_matched' if observed == expected else 'assertion_failed')
    except (OSError, sqlite3.Error, RuntimeError):
        pass
    return row


def run(manifest_sha256, *, authorized=False):
    if not authorized or not isinstance(manifest_sha256, str) or not re.fullmatch('[a-f0-9]{64}', manifest_sha256):
        raise ValueError('authorization_or_identity_required')
    rows = [check(case) for case in CASES]
    counts = {state: sum(row['state'] == state for row in rows) for state in ('PASS','FAIL','BLOCKED')}
    state = ('BLOCKED' if not rows or counts['BLOCKED'] or sum(counts.values()) != len(rows)
             else 'FAIL' if counts['FAIL'] else 'PASS')
    return dict(schema='vulcanary.synthetic-storage-run.v1', producer_version=__version__,
                implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                run_id=str(uuid.uuid4()), finished_at=datetime.now(timezone.utc).isoformat(),
                state=state, counts=counts, checks=rows, policy_effect='none', independent_certification=False,
                manifest_sha256=manifest_sha256, candidate_binding='operator-declared-reference',
                evidence_method='bundled-sqlite-storage-contract',
                runtime={'python':sys.version.split()[0], 'sqlite':sqlite3.sqlite_version},
                limits={'capacity_probe_bytes':131072, 'sqlite_lock_timeout_seconds':0.2, 'cases':len(CASES)},
                limitations=[
                    'Bundled reference storage only; no Zirze, Android, iOS, browser keystore or deployed backend was tested.',
                    'No cryptographic operations: fixed synthetic bytes are not real keys.',
                    'SQLite FULL is caused by a database page limit, not a full host/device disk.',
                    'Lost acknowledgement and storage refusals are synchronous injected boundaries, not native process termination or network faults.',
                    'Account epoch is synthetic; no real login, logout, RLS, identity provider or account switch is exercised.',
                    'Temporary fixtures are not an OS sandbox; no target-supplied code or external tool is executed.',
                    'Fresh connections verify committed state, not power-loss durability.'])


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output/'report.json', report)
    lines = ['# Bundled storage fault checks', '', 'State: '+report['state'], '']
    for row in report['checks']:
        lines += [f"- {row['id']}: {row['state']} ({row['reason']}); cleanup: {row['cleanup']}",
                  '  Expected: '+json.dumps(row['expected']), '  Observed: '+json.dumps(row['observed'])]
    lines += [''] + ['- '+item for item in report['limitations']]
    lines += ['', 'Checksums are unsigned integrity checks, not authentication or certification.']
    with (output/'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines)+'\n')
    write_new(output/'checksums.json', {name:hashlib.sha256((output/name).read_bytes()).hexdigest()
                                      for name in ('report.json','reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--authorize-disposable-storage', action='store_true')
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('existing_output')
        report = run(args.manifest_sha256, authorized=args.authorize_disposable_storage)
        export(report,args.output)
        print(json.dumps({'state':report['state'], 'counts':report['counts']}))
        return 0 if report['state']=='PASS' else 1 if report['state']=='FAIL' else 2
    except (OSError,ValueError,TypeError):
        print('Storage checks blocked. Authorize disposable fixtures, supply a manifest digest and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
