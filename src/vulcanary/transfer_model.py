"""Bundled synthetic transfer reference model, never application or crypto evidence."""
import hashlib
from pathlib import Path
import secrets
import sqlite3
import tempfile
from functools import wraps


SCENARIOS = (
    'approval', 'refusal', 'offline_before_upload', 'lost_upload_response',
    'lost_completion_response', 'account_switch', 'partial_install', 'failed_readback',
    'storage_failure', 'restart_after_receipt', 'duplicate_install', 'cancel_before_claim',
    'expiry_before_claim', 'second_receiver', 'stale_response', 'source_preserved',
)


class Interrupted(Exception):
    pass


def recorded(method):
    @wraps(method)
    def invoke(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        outcome = ('accepted' if result else 'refused') if type(result) is bool else result
        self.events.append({'operation': method.__name__, 'outcome': outcome})
        return result
    return invoke


class Model:
    def __init__(self, root, defect=None):
        self.path = root / 'model.sqlite'
        self.db = sqlite3.connect(self.path)
        self.db.executescript('''
            CREATE TABLE relay (id INTEGER PRIMARY KEY, approved INTEGER, revoked INTEGER,
                                expiry INTEGER, claimed TEXT, exports INTEGER, complete INTEGER);
            INSERT INTO relay VALUES(1,0,0,10,NULL,0,0);
            CREATE TABLE keys (version INTEGER PRIMARY KEY, value BLOB);
            CREATE TABLE receipt (id INTEGER PRIMARY KEY);
        ''')
        self.db.commit()
        self.source = (secrets.token_bytes(32), secrets.token_bytes(32))
        self.source_hash = hashlib.sha256(b''.join(self.source)).digest()
        self.account = 'receiver'
        self.defect = defect
        self.install_writes = 0
        self.events = []

    def close(self):
        self.db.close()

    def restart(self):
        self.db.close()
        self.db = sqlite3.connect(self.path)
        self.events.append({'operation': 'restart', 'outcome': 'database_reopened'})

    def approve(self):
        with self.db:
            self.db.execute('UPDATE relay SET approved=1')

    def available(self, now=0):
        approved, revoked, expiry = self.db.execute('SELECT approved, revoked, expiry FROM relay').fetchone()
        return (approved or self.defect == 'allow_unapproved') and not revoked and now < expiry

    @recorded
    def upload(self, loss=False, offline=False):
        if offline or not self.available():
            return 'refused'
        with self.db:
            self.db.execute('UPDATE relay SET exports=exports+1 WHERE exports=0')
            if self.defect == 'reexport':
                self.db.execute('UPDATE relay SET exports=exports+1')
        return 'uncertain' if loss else 'uploaded'

    @recorded
    def claim(self, receiver='device-a', now=0):
        if not self.available(now):
            return False
        with self.db:
            current, exports = self.db.execute('SELECT claimed,exports FROM relay').fetchone()
            if not exports or (current is not None and current != receiver):
                return False
            self.db.execute('UPDATE relay SET claimed=?', (receiver,))
        return True

    @recorded
    def install(self, session='receiver', fault=None):
        if self.account != session and self.defect != 'ignore_account':
            return 'refused'
        if not self.available() or not self.db.execute('SELECT claimed FROM relay').fetchone()[0]:
            return 'refused'
        if self.db.execute('SELECT count(*) FROM receipt').fetchone()[0] and self.defect != 'duplicate_install':
            return 'already_installed'
        try:
            with self.db:
                for version, value in enumerate(self.source, 1):
                    self.db.execute('INSERT OR REPLACE INTO keys VALUES(?,?)', (version, value))
                    if self.defect == 'non_atomic' and fault:
                        self.db.commit()
                    if fault in ('partial_install', 'storage_failure'):
                        raise Interrupted()
                if fault == 'failed_readback':
                    raise Interrupted()
                self.db.execute('INSERT OR REPLACE INTO receipt VALUES(1)')
            self.install_writes += 1
            if self.defect == 'corrupt_source':
                self.source = (b'changed', b'changed')
            return 'installed'
        except Interrupted:
            return 'interrupted'

    @recorded
    def complete(self, loss=False):
        if not self.db.execute('SELECT count(*) FROM receipt').fetchone()[0]:
            return 'refused'
        with self.db:
            self.db.execute('UPDATE relay SET complete=1')
        return 'uncertain' if loss else 'complete'

    def readable(self):
        return tuple(row[0] for row in self.db.execute('SELECT value FROM keys ORDER BY version')) == self.source


def exercise(model, scenario):
    """Assertions use actual observed state, not a scenario-to-PASS lookup."""
    def require(condition):
        if not condition:
            raise AssertionError('synthetic invariant mismatch')
    if scenario == 'refusal':
        require(model.upload() == 'refused')
        require(not model.claim())
        require(not model.readable())
        return
    model.approve()
    if scenario == 'offline_before_upload':
        require(model.upload(offline=True) == 'refused')
        require(model.db.execute('SELECT exports FROM relay').fetchone()[0] == 0)
        return
    require(model.upload(loss=scenario == 'lost_upload_response') ==
            ('uncertain' if scenario == 'lost_upload_response' else 'uploaded'))
    if scenario == 'lost_upload_response':
        model.restart()
        require(model.upload() == 'uploaded')
        require(model.db.execute('SELECT exports FROM relay').fetchone()[0] == 1)
    if scenario == 'cancel_before_claim':
        with model.db:
            model.db.execute('UPDATE relay SET revoked=1')
        require(not model.claim())
        require(not model.readable())
        return
    if scenario == 'expiry_before_claim':
        require(not model.claim(now=10))
        require(not model.readable())
        return
    require(model.claim())
    if scenario == 'second_receiver':
        require(not model.claim('device-b'))
    if scenario in ('account_switch', 'stale_response'):
        model.account = 'other-account'
        require(model.install(session='receiver') == 'refused')
        require(not model.readable())
        return
    if scenario in ('partial_install', 'failed_readback', 'storage_failure'):
        require(model.install(fault=scenario) == 'interrupted')
        model.restart()
        require(model.db.execute('SELECT count(*) FROM keys').fetchone()[0] == 0)
        require(model.db.execute('SELECT count(*) FROM receipt').fetchone()[0] == 0)
    require(model.install() == 'installed')
    require(model.readable())
    require(hashlib.sha256(b''.join(model.source)).digest() == model.source_hash)
    if scenario in ('restart_after_receipt', 'duplicate_install'):
        writes = model.install_writes
        model.restart()
        require(model.install() == 'already_installed')
        require(model.install_writes == writes)
        require(model.upload() == 'uploaded')
        require(model.db.execute('SELECT exports FROM relay').fetchone()[0] == 1)
    outcome = model.complete(loss=scenario == 'lost_completion_response')
    require(outcome == ('uncertain' if scenario == 'lost_completion_response' else 'complete'))
    if scenario == 'lost_completion_response':
        model.restart()
        require(model.db.execute('SELECT complete FROM relay').fetchone()[0] == 1)
        require(model.install() == 'already_installed')
        require(model.complete() == 'complete')
    require(model.readable())


def run_scenarios(*, defect=None):
    if defect not in (None, 'allow_unapproved', 'ignore_account', 'non_atomic',
                      'duplicate_install', 'reexport', 'corrupt_source'):
        raise ValueError('unknown control')
    results = []
    for scenario in SCENARIOS:
        state = 'BLOCKED'
        try:
            with tempfile.TemporaryDirectory(prefix='vulcanary-transfer-model-') as directory:
                model = Model(Path(directory), defect)
                try:
                    exercise(model, scenario)
                    state = 'PASS'
                except AssertionError:
                    state = 'FAIL'
                finally:
                    model.close()
            results.append({'scenario': scenario, 'state': state, 'evidence_level': 'mock',
                            'cleanup': 'complete', 'events': model.events})
        except (OSError, sqlite3.Error):
            results.append({'scenario': scenario, 'state': 'BLOCKED', 'evidence_level': 'mock',
                            'cleanup': 'unconfirmed', 'events': []})
    return results
