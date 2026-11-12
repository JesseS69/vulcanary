"""Disposable SQLite permission and claim-race contracts, not deployed RLS tests."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from queue import Queue
import re
import sqlite3
import sys
import tempfile
import threading
import time
import uuid

from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

CASES = ('cross-account-read', 'cross-account-write', 'expired-session',
         'logged-out-session', 'unapproved-claim', 'expired-transfer',
         'revoked-transfer', 'concurrent-receivers')
NOW = 10
RACE_REPETITIONS = 5


class Fixture:
    def __init__(self, directory, defect=None):
        self.path = directory/'synthetic.sqlite'
        self.defect = defect
        with closing(self.connect()) as db, db:
            db.executescript('''
                CREATE TABLE transfer (id INTEGER PRIMARY KEY, tenant TEXT, approved INTEGER,
                    revoked INTEGER, expires INTEGER, claimed TEXT);
                INSERT INTO transfer VALUES (1,'owner',1,0,20,NULL);
                CREATE TABLE session (id TEXT PRIMARY KEY, tenant TEXT, expires INTEGER, active INTEGER);
                INSERT INTO session VALUES ('receiver-a','owner',20,1), ('receiver-b','owner',20,1),
                    ('outsider','other',20,1), ('expired','owner',5,1), ('logged-out','owner',20,0);
            ''')

    def connect(self):
        return sqlite3.connect(self.path, timeout=1)

    def tenant(self, db, session):
        row = db.execute('SELECT tenant,expires,active FROM session WHERE id=?', (session,)).fetchone()
        if row is None or (self.defect != 'bypass-session' and (row[1] <= NOW or not row[2])):
            return None
        return 'owner' if self.defect == 'bypass-tenant' else row[0]

    def read(self, session):
        with closing(self.connect()) as db:
            tenant = self.tenant(db, session)
            return db.execute('SELECT id FROM transfer WHERE id=1 AND tenant=?', (tenant,)).fetchone() is not None

    def claim(self, session):
        with closing(self.connect()) as db, db:
            tenant = self.tenant(db, session)
            # One conditional UPDATE, not a check-then-write in application memory.
            return db.execute('''UPDATE transfer SET claimed=?
                WHERE id=1 AND tenant=? AND (revoked=0 OR ?)
                AND (approved=1 OR ?) AND (expires>? OR ?) AND (claimed IS NULL OR ?)''',
                (session, tenant, self.defect == 'bypass-revocation', self.defect == 'bypass-approval', NOW,
                 self.defect == 'bypass-expiry', self.defect == 'unchecked-claim')).rowcount == 1

    def snapshot(self):
        with closing(self.connect()) as db:
            return db.execute('SELECT * FROM transfer ORDER BY id').fetchall()

    def change(self, case):
        statements = {'unapproved-claim': 'UPDATE transfer SET approved=0',
                      'expired-transfer': 'UPDATE transfer SET expires=10',
                      'revoked-transfer': 'UPDATE transfer SET revoked=1'}
        if case in statements:
            with closing(self.connect()) as db, db:
                db.execute(statements[case])


def race(fixture):
    barrier = threading.Barrier(2, timeout=2)
    results = Queue()

    def contender(session):
        try:
            barrier.wait()
            results.put((session, fixture.claim(session)))
        except (sqlite3.Error, threading.BrokenBarrierError):
            results.put((session, None))

    threads = [threading.Thread(target=contender, args=(session,), daemon=True)
               for session in ('receiver-a', 'receiver-b')]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 5
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads) or results.qsize() != 2:
        raise RuntimeError('workers_incomplete')
    outcomes = [results.get_nowait() for _ in threads]
    if any(accepted is None for _, accepted in outcomes):
        raise RuntimeError('database_or_barrier_failed')
    winners = [session for session, accepted in outcomes if accepted]
    final_claimant = fixture.snapshot()[0][-1]
    return {'attempts': 2, 'accepted': len(winners), 'denied': 2-len(winners),
            'stored_winner_matches': len(winners) == 1 and final_claimant == winners[0]}


def check(case, *, defect=None):
    if case not in CASES:
        raise ValueError('unsupported_case')
    expected = ({'attempts': 2, 'accepted': 1, 'denied': 1, 'stored_winner_matches': True}
                if case == 'concurrent-receivers' else {'allowed': False, 'state_unchanged': True})
    row = {'id': case, 'state': 'BLOCKED', 'expected': expected, 'observations': [],
           'reason': 'execution_incomplete', 'cleanup': 'unconfirmed'}
    try:
        repetitions = RACE_REPETITIONS if case == 'concurrent-receivers' else 1
        for _ in range(repetitions):
            with tempfile.TemporaryDirectory(prefix='vulcanary-synthetic-db-') as directory:
                fixture = Fixture(Path(directory), defect)
                fixture.change(case)
                before = fixture.snapshot()
                if case == 'concurrent-receivers':
                    observed = race(fixture)
                else:
                    session = {'cross-account-read': 'outsider', 'cross-account-write': 'outsider',
                               'expired-session': 'expired', 'logged-out-session': 'logged-out'}.get(case, 'receiver-a')
                    allowed = fixture.read(session) if case == 'cross-account-read' else fixture.claim(session)
                    observed = {'allowed': allowed, 'state_unchanged': before == fixture.snapshot()}
                row['observations'].append(observed)
        if repetitions < 1 or len(row['observations']) != repetitions:
            raise RuntimeError('missing_observations')
        matched = all(value == expected for value in row['observations'])
        row.update(state='PASS' if matched else 'FAIL', cleanup='complete',
                   reason='assertions_matched' if matched else 'assertion_failed')
    except (OSError, sqlite3.Error, RuntimeError):
        pass
    return row


def run(manifest_sha256, *, authorized=False):
    if not authorized or not re.fullmatch(r'[a-f0-9]{64}', manifest_sha256):
        raise ValueError('authorization_or_identity_required')
    rows = [check(case) for case in CASES]
    counts = {state: sum(row['state'] == state for row in rows) for state in ('PASS', 'FAIL', 'BLOCKED')}
    return {'schema': 'vulcanary.synthetic-database-run.v1', 'producer_version': __version__,
            'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'run_id': str(uuid.uuid4()), 'finished_at': datetime.now(timezone.utc).isoformat(),
            'state': 'BLOCKED' if counts['BLOCKED'] else 'FAIL' if counts['FAIL'] else 'PASS',
            'counts': counts, 'policy_effect': 'none', 'independent_certification': False,
            'manifest_sha256': manifest_sha256, 'candidate_binding': 'operator-declared-reference',
            'evidence_method': 'bundled-sqlite-contract', 'checks': rows,
            'runtime': {'python': sys.version.split()[0], 'sqlite': sqlite3.sqlite_version},
            'limits': {'database_lock_timeout_seconds': 1, 'race_join_seconds': 5,
                       'race_repetitions': RACE_REPETITIONS, 'contenders_per_race': 2},
            'reproduce': 'python -m vulcanary.database_tests --authorize-disposable-database --manifest-sha256 ' + manifest_sha256 + ' --output NEW_DIRECTORY',
            'limitations': ['Only a bundled reference schema and query predicates were tested, not an application schema or deployed database.',
                            'SQLite has no deployed row-level security policies here; denial depends on these bundled query predicates, not database-user privileges.',
                            'Two independent connections contend from separate threads; five races are samples, not proof of every possible schedule.',
                            'Session identity and time are synthetic fixed inputs; no identity provider, credentials, logout transport or device account switching is tested.',
                            'The manifest reference is operator-declared and cannot close application database or authorization requirements.']}


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output/'report.json', report)
    lines = ['# Bundled database contract tests', '', 'State: ' + report['state'], '']
    for row in report['checks']:
        lines += [f"- {row['id']}: {row['state']} ({row['reason']}); cleanup: {row['cleanup']}",
                  '  Expected: ' + json.dumps(row['expected']), '  Observed: ' + json.dumps(row['observations'])]
    lines += [''] + ['- ' + value for value in report['limitations']]
    lines += ['', 'Checksums are unsigned; this is not independent certification.']
    with (output/'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    write_new(output/'checksums.json', {name: hashlib.sha256((output/name).read_bytes()).hexdigest() for name in ('report.json', 'reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--authorize-disposable-database', action='store_true')
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('existing_output')
        report = run(args.manifest_sha256, authorized=args.authorize_disposable_database)
        export(report, args.output)
        print(json.dumps({'state': report['state'], 'counts': report['counts']}))
        return 0 if report['state'] == 'PASS' else 1 if report['state'] == 'FAIL' else 2
    except (OSError, ValueError, TypeError):
        print('Database contract test blocked. Authorize disposable fixtures, supply a manifest digest and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
