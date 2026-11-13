import contextlib
import io
import json
import random
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from vulcanary import android_inventory as inv

SERIAL = 'SYNTHETIC_DEVICE'
PACKAGE = 'org.example.inventory'
NONCE = 'a' * 32


def response(nonce=NONCE):
    sections = [('release', '15'), ('api', '35'), ('model', 'Synthetic Phone'),
                ('version_before', f'package:{PACKAGE} versionCode:31'),
                ('paths_before', 'package:/data/app/private/base.apk\npackage:/data/app/private/split.apk'),
                ('version_after', f'package:{PACKAGE} versionCode:31'),
                ('paths_after', 'package:/data/app/private/base.apk\npackage:/data/app/private/split.apk')]
    return (''.join(f'{nonce}:{key}\n{value}\n' for key, value in sections) + f'{nonce}:end\n').encode()


def frame(channel, data):
    return struct.pack('<BI', channel, len(data)) + data


class Server:
    """Owned loopback fixture. Never invokes adb or contacts any real device."""
    def __init__(self, payload=None, *, delay=0, refuse=False, fragment=False, byte_delay=0):
        self.payload = payload if payload is not None else frame(1, response()) + frame(3, b'\0')
        self.delay, self.refuse, self.fragment = delay, refuse, fragment
        self.byte_delay = byte_delay
        self.requests, self.errors = [], []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.thread = threading.Thread(target=self.run)

    def read(self, conn, n):
        data = b''
        while len(data) < n:
            part = conn.recv(n - len(data))
            if not part:
                raise EOFError()
            data += part
        return data

    def request(self, conn):
        value = self.read(conn, int(self.read(conn, 4), 16)).decode()
        self.requests.append(value)
        return value

    def run(self):
        try:
            with self.listener.accept()[0] as conn:
                conn.settimeout(3)
                self.request(conn)
                if self.refuse:
                    conn.sendall(b'FAIL000cPRIVATE_TEXT')
                    return
                conn.sendall(b'OKAY')
                self.request(conn)
                conn.sendall(b'OKAY')
                self.requests.append(self.read(conn, 5))
                if self.delay:
                    time.sleep(self.delay)
                if self.fragment:
                    for byte in self.payload:
                        if self.byte_delay:
                            time.sleep(self.byte_delay)
                        conn.sendall(bytes([byte]))
                else:
                    conn.sendall(self.payload)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # expected client refusal
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            self.listener.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.thread.join(4)
        if self.thread.is_alive() or self.errors:
            raise RuntimeError('fake server did not complete: ' + str(self.errors))


def inspect(**kwargs):
    with patch.object(inv.secrets, 'token_hex', return_value=NONCE):
        return inv.inspect(SERIAL, PACKAGE, authorized=True, trust_existing_server=True, **kwargs)


class AndroidInventoryTests(unittest.TestCase):
    def test_real_loopback_protocol_fixed_services_and_sanitized_inventory(self):
        with Server(fragment=True) as server:
            report = inspect(port=server.port)
        self.assertEqual(server.requests, ['host:transport:' + SERIAL,
                         'shell,v2,raw:' + inv.commands(PACKAGE, 0, NONCE), struct.pack('<BI', 4, 0)])
        self.assertEqual(report['state'], 'NOT_RUN')
        self.assertEqual(report['collection_state'], 'COMPLETE')
        self.assertEqual(report['observations']['version_code'], 31)
        self.assertEqual(report['observations']['apk_path_count'], 2)
        self.assertFalse(report['application_executed'])
        self.assertEqual(report['policy_effect'], 'none')
        serialized = json.dumps(report)
        for value in (SERIAL, PACKAGE, 'Synthetic Phone', '/data/app/private', NONCE):
            self.assertNotIn(value, serialized)

    def test_auth_validation_refuses_before_socket(self):
        with patch.object(inv.socket, 'socket', side_effect=AssertionError('must not connect')):
            self.assertEqual(inv.inspect(SERIAL, PACKAGE)['reason'], 'authorization_required')
            self.assertEqual(inv.inspect(SERIAL, PACKAGE, authorized=True)['reason'], 'authorization_required')
            invalid = [dict(serial='phone;id'), dict(serial='host:kill'), dict(serial='1.2.3.4:5555'),
                       dict(package='org.example;id'), dict(package='-x'), dict(user=-1), dict(user=True),
                       dict(port=0), dict(timeout=float('nan')), dict(timeout=float('inf')), dict(timeout=31)]
            for changes in invalid:
                args = dict(serial=SERIAL, package=PACKAGE, authorized=True, trust_existing_server=True)
                args.update(changes)
                self.assertEqual(inv.inspect(**args)['state'], 'BLOCKED')

    def test_protocol_refusals_clear_observations_and_never_reconnect(self):
        cases = [b'', frame(1, response()), frame(2, b'SECRET'), frame(3, b'\1'),
                 frame(1, response()) + frame(3, b'\0') + b'trailing',
                 frame(3, b'\0\0'), frame(9, b''), struct.pack('<BI', 1, inv.MAX_FRAME + 1),
                 b'\1\0', frame(1, b'x') * (inv.MAX_FRAMES + 1)]
        for payload in cases:
            with self.subTest(payload=payload[:10]), Server(payload) as server:
                report = inspect(port=server.port)
            self.assertEqual(report['state'], 'BLOCKED')
            self.assertIsNone(report['observations'])
            self.assertEqual(len(server.requests), 3)
            self.assertNotIn('SECRET', json.dumps(report))
        with Server(refuse=True) as server:
            report = inspect(port=server.port)
        self.assertEqual(len(server.requests), 1)
        self.assertNotIn('PRIVATE_TEXT', json.dumps(report))
        self.assertEqual(report['state'], 'BLOCKED')

    def test_deadline_is_bounded_and_observed(self):
        with Server(delay=.2) as server:
            report = inspect(port=server.port, timeout=.05)
        self.assertEqual(report['reason'], 'deadline_reached')
        self.assertLess(report['elapsed_seconds'], 1)
        self.assertIsNone(report['observations'])

    def test_continuous_partial_reads_do_not_refresh_total_deadline(self):
        with Server(fragment=True, byte_delay=.02) as server:
            report = inspect(port=server.port, timeout=.08)
        self.assertEqual(report['reason'], 'deadline_reached')
        self.assertLess(report['elapsed_seconds'], .8)
        self.assertIsNone(report['observations'])

    def test_seeded_metadata_mutations_never_crash_or_claim_security_pass(self):
        rng = random.Random(7069)
        base = response()
        for _ in range(240):
            raw = bytearray(base)
            start = rng.randrange(len(raw))
            mode = rng.randrange(5)
            if mode == 0:
                del raw[start:]
            elif mode == 1:
                raw[start] = rng.randrange(256)
            elif mode == 2:
                raw[start:start] = b'\x00\xffPRIVATE_MARKER'
            elif mode == 3:
                raw[start:start] = raw[:rng.randrange(100)]
            else:
                raw[start:start] = b'x' * 50000
            with patch.object(inv, 'collect', return_value=bytes(raw)):
                report = inspect()
            self.assertIn(report['state'], ('NOT_RUN', 'BLOCKED'))
            self.assertNotIn('PRIVATE_MARKER', json.dumps(report))
            if report['state'] == 'BLOCKED':
                self.assertIsNone(report['observations'])

    def test_total_output_and_zero_frame_limits(self):
        payload = frame(1, b'x' * inv.MAX_FRAME) * 5
        for value in (payload, frame(1, b'') * (inv.MAX_FRAMES + 1)):
            with Server(value) as server:
                report = inspect(port=server.port)
            self.assertEqual(report['state'], 'BLOCKED')
            self.assertIsNone(report['observations'])

    def test_metadata_mutations_fail_closed(self):
        original = response()
        cases = [original.replace(b'versionCode:31', b'versionCode:32', 1),
                 original.replace(b'base.apk', b'changed.apk', 1),
                 original.replace(PACKAGE.encode(), b'org.example.wrong'),
                 original.replace(b'package:/data/app/private/base.apk\n', b'', 1),
                 original.replace(b'package:/data/app/private/base.apk', b'package:/data/../base.apk'),
                 original.replace(b':end\n', b':end\nextra\n'), b'\xff' + original,
                 original.replace(b':api\n35', b':api\nunknown'),
                 original.replace(b':model\nSynthetic Phone', b':model\nprivate\x00value'),
                 original.replace(b':end\n', b':model\nrepeated\n'),
                 original.replace(b'versionCode:31', b'versionCode:9223372036854775808')]
        for raw in cases:
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                inv.parse(raw, PACKAGE, NONCE)
        self.assertEqual(inv.parse(original.replace(b'\n', b'\r\n'), PACKAGE, NONCE)['version_code'], 31)

    def test_completed_metadata_is_never_security_pass_and_existing_output_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'new'
            with Server() as server, patch.object(inv.secrets, 'token_hex', return_value=NONCE), contextlib.redirect_stdout(io.StringIO()):
                args = ['--serial', SERIAL, '--package', PACKAGE, '--server-port', str(server.port),
                        '--authorize-read-only-inventory', '--trust-existing-local-adb-server', '--output', str(output)]
                self.assertEqual(inv.main(args), 2)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['collection_state'], 'COMPLETE')
            self.assertEqual(report['state'], 'NOT_RUN')
            before = (output / 'report.json').read_bytes()
            with patch.object(inv.socket, 'socket', side_effect=AssertionError('must not connect')), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(inv.main(args), 2)
            self.assertEqual((output / 'report.json').read_bytes(), before)
            for file in output.iterdir():
                for secret in (SERIAL, PACKAGE, '/data/app/private', 'Synthetic Phone'):
                    self.assertNotIn(secret, file.read_text())

    def test_package_substring_neighbors_never_substitute_for_exact_target(self):
        raw = response()
        exact = f'package:{PACKAGE} versionCode:31'.encode()
        neighbor = f'package:{PACKAGE}.debug versionCode:99'.encode()
        self.assertEqual(inv.parse(raw.replace(exact, neighbor + b'\n' + exact), PACKAGE, NONCE)['version_code'], 31)
        for changed in (raw.replace(exact, neighbor), raw.replace(exact, exact + b'\n' + exact),
                        raw.replace(exact, neighbor + b'\nmalformed\n' + exact)):
            with self.assertRaises(ValueError):
                inv.parse(changed, PACKAGE, NONCE)

    def test_unavailable_server_does_not_launch_anything(self):
        with patch.object(inv.socket, 'socket', side_effect=ConnectionRefusedError()), patch('subprocess.Popen', side_effect=AssertionError('no process')):
            report = inspect()
        self.assertEqual(report['reason'], 'connection_unavailable_or_interrupted')
        self.assertIsNone(report['observations'])


if __name__ == '__main__':
    unittest.main()
