"""Owned-loopback HTTP response-loss checks against a bundled synthetic relay."""
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import uuid

from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

SCENARIOS = ('before-upload-commit', 'lost-upload-response', 'lost-completion-response')
SOCKET_TIMEOUT = 1.0


class _Server(HTTPServer):
    allow_reuse_address = False

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(SOCKET_TIMEOUT)
        return connection, address

    def handle_error(self, request, client_address):
        # A client sees failure/uncertainty; never print source, headers or tracebacks.
        self.failed = True


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        server = self.server
        if (not hmac.compare_digest(self.headers.get('X-Synthetic-Run', ''), server.token)
                or self.path not in ('/upload', '/complete')
                or self.headers.get('Content-Length') != '0'
                or self.headers.get('Transfer-Encoding') is not None):
            self.send_error(403)
            return
        operation = self.path[1:]
        lose_response = server.drop_operation == operation and not server.dropped
        if lose_response:
            server.dropped = True
        if not (lose_response and server.drop_before_commit):
            with closing(sqlite3.connect(server.database, timeout=0.2)) as database, database:
                if operation == 'complete' and not database.execute("SELECT 1 FROM writes WHERE operation='upload'").fetchone():
                    self.send_error(409)
                    return
                if server.broken_duplicates:
                    database.execute('INSERT INTO writes VALUES (?,1) ON CONFLICT(operation) DO UPDATE SET count=count+1', (operation,))
                else:
                    database.execute('INSERT OR IGNORE INTO writes VALUES (?,1)', (operation,))
            server.events.append({'operation': operation, 'server_outcome': 'committed'})
        else:
            server.events.append({'operation': operation, 'server_outcome': 'not_committed'})
        if lose_response:
            # The transaction above is closed/committed BEFORE the socket is dropped.
            server.events.append({'operation': operation, 'transport_outcome': 'response_dropped'})
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')


@contextmanager
def _relay(directory, scenario, broken_duplicates=False):
    database = directory / 'synthetic.sqlite'
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute('CREATE TABLE writes (operation TEXT PRIMARY KEY, count INTEGER NOT NULL)')
    server = _Server(('127.0.0.1', 0), _Handler)
    server.database = database
    server.token = secrets.token_hex(32)
    server.events = []
    server.failed = False
    server.dropped = False
    server.drop_operation = 'complete' if scenario == 'lost-completion-response' else 'upload'
    server.drop_before_commit = scenario == 'before-upload-commit'
    server.broken_duplicates = broken_duplicates
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise RuntimeError('cleanup_incomplete')


def _request(server, operation):
    # No URL argument, DNS, redirect handling, proxy inheritance or remote adapter.
    client = HTTPConnection('127.0.0.1', server.server_port, timeout=SOCKET_TIMEOUT)
    try:
        client.request('POST', '/' + operation, body=b'', headers={'X-Synthetic-Run': server.token})
        response = client.getresponse()
        body = response.read(3)
        return 'acknowledged' if response.status == 200 and body == b'OK' else 'rejected'
    except (OSError, HTTPException):
        return 'uncertain'
    finally:
        client.close()


def _counts(server):
    with closing(sqlite3.connect(server.database, timeout=0.2)) as connection:
        return dict(connection.execute('SELECT operation, count FROM writes'))


def _require(condition):
    # Assertions are behavior, and must still run under python -O.
    if not condition:
        raise AssertionError('synthetic_contract_failed')


def scenario(name, *, broken_duplicates=False):
    if name not in SCENARIOS:
        raise ValueError('unsupported_scenario')
    started = time.monotonic()
    events = []
    result = {'id': name, 'state': 'BLOCKED', 'reason': 'execution_incomplete',
              'cleanup': 'unconfirmed', 'events': events,
              'expected': {'first_client_outcome': 'uncertain',
                           'first_committed_writes': 0 if name == 'before-upload-commit' else 1,
                           'retry_client_outcome': 'acknowledged', 'final_committed_writes': 1}}
    try:
        with tempfile.TemporaryDirectory(prefix='vulcanary-synthetic-http-') as temporary:
            with _relay(Path(temporary), name, broken_duplicates) as server:
                operation = server.drop_operation
                if operation == 'complete':
                    _require(_request(server, 'upload') == 'acknowledged')
                first = _request(server, operation)
                first_count = _counts(server).get(operation, 0)
                events.append({'attempt': 1, 'operation': operation, 'client_outcome': first,
                               'committed_writes': first_count})
                _require(first == 'uncertain')
                _require(first_count == (0 if server.drop_before_commit else 1))
                second = _request(server, operation)
                count = _counts(server).get(operation, 0)
                events.append({'attempt': 2, 'operation': operation, 'client_outcome': second,
                               'committed_writes': count})
                _require(second == 'acknowledged' and count == 1)
                _require(not server.failed)
                events.extend(server.events)
        result.update(state='PASS', reason='assertions_matched', cleanup='complete')
    except AssertionError:
        result.update(state='FAIL', reason='assertion_failed', cleanup='complete')
    except (OSError, sqlite3.Error, RuntimeError):
        pass
    result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return result


def run(manifest_sha256, *, authorized=False):
    if not authorized or not re.fullmatch(r'[a-f0-9]{64}', manifest_sha256):
        raise ValueError('authorization_or_identity_required')
    rows = [scenario(name) for name in SCENARIOS]
    counts = {state: sum(row['state'] == state for row in rows) for state in ('PASS', 'FAIL', 'BLOCKED')}
    state = 'BLOCKED' if counts['BLOCKED'] else 'FAIL' if counts['FAIL'] else 'PASS'
    return {'schema': 'vulcanary.synthetic-transport-run.v1', 'producer_version': __version__,
            'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'run_id': str(uuid.uuid4()), 'finished_at': datetime.now(timezone.utc).isoformat(),
            'state': state, 'counts': counts, 'policy_effect': 'none', 'independent_certification': False,
            'manifest_sha256': manifest_sha256, 'candidate_binding': 'operator-declared-reference',
            'evidence_method': 'bundled-relay-owned-loopback-http', 'scenarios': rows,
            'runtime': {'python': sys.version.split()[0], 'sqlite': sqlite3.sqlite_version},
            'reproduce': 'python -m vulcanary.transport_tests --authorize-owned-loopback --manifest-sha256 ' + manifest_sha256 + ' --output NEW_DIRECTORY',
            'limits': {'socket_timeout_seconds': SOCKET_TIMEOUT, 'requests_per_scenario_max': 3},
            'limitations': ['Only the bundled synthetic relay was tested; no application or deployed backend was contacted.',
                            'Real loopback sockets and disposable SQLite commits are used; this is not deployed RLS, TLS, native process death or device-storage evidence.',
                            'The before-commit failure reaches the local server, which drops it without a write; it does not simulate an offline device.',
                            'Completion retries test idempotent relay writes, not actual key installation or cryptographic correctness.',
                            'A manifest reference does not prove the candidate implements this model; these results do not close application requirements.']}


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output / 'report.json', report)
    lines = ['# Bundled synthetic HTTP fault tests', '', 'State: ' + report['state'], '']
    lines += [f"- {row['id']}: {row['state']} ({row['reason']}); cleanup: {row['cleanup']}" for row in report['scenarios']]
    lines += [''] + ['- ' + value for value in report['limitations']]
    lines += ['', 'Checksums are unsigned; this is not independent certification.']
    with (output/'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    write_new(output/'checksums.json', {name: hashlib.sha256((output/name).read_bytes()).hexdigest() for name in ('report.json', 'reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--authorize-owned-loopback', action='store_true')
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('existing_output')
        report = run(args.manifest_sha256, authorized=args.authorize_owned_loopback)
        export(report, args.output)
        print(json.dumps({'state': report['state'], 'counts': report['counts']}))
        return 2 if report['state'] == 'BLOCKED' else 1 if report['state'] == 'FAIL' else 0
    except (OSError, ValueError, TypeError):
        print('Synthetic transport test blocked. Authorize the owned loopback fixture, supply a manifest digest and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
