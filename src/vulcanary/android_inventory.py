"""Opt-in read-only metadata inventory through an existing local ADB server."""
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import socket
import struct
import time

from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

MAX_OUTPUT = 262144
MAX_FRAMES = 1024
MAX_FRAME = 65536
MAX_APKS = 128
LIMITATIONS = [
    'Inventory completion is NOT_RUN for security testing; no security PASS or independent certification is produced.',
    'The existing loopback ADB server and selected device are trusted, not authenticated by this protocol. A serial is a selector, not hardware attestation.',
    'No host executable or daemon is launched. No server lifecycle, pairing, network-device connection, enumeration, application launch, APK copying or application-data access is performed.',
    'Fixed Android OS shell utilities read metadata. Read-only does not mean no OS auditing or incidental system activity.',
    'Two matching package snapshots detect some changes, not changes that occur and revert between observations or an atomic device snapshot.',
    'Version code and path digests do not establish APK bytes, signing, AAB lineage, version name, completeness of installed splits or runtime behavior.',
    'Device, package and path hashes are unsigned identifiers, not encryption or authentication. Raw responses and exception text are not exported.',
    'The deadline bounds the client connection; closing it is not proof that a remote OS utility terminated.',
]


class Refused(ValueError):
    pass


def require(condition):
    if not condition:
        raise Refused('unsupported_response')


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def validate(serial, package, user, port, timeout):
    # Serial syntax deliberately excludes network transport selectors and delimiters.
    require(isinstance(serial, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', serial))
    require(isinstance(package, str) and len(package) <= 255 and
            re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', package))
    require(type(user) is int and 0 <= user <= 2147483647)
    require(type(port) is int and 1 <= port <= 65535)
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 30)


def commands(package, user, nonce):
    """Only called after validation. No caller-supplied shell fragment is accepted."""
    validate('validated-selector', package, user, 5037, 10)
    require(isinstance(nonce, str) and re.fullmatch('[a-f0-9]{32}', nonce))
    queries = [
        ('release', '/system/bin/getprop ro.build.version.release'),
        ('api', '/system/bin/getprop ro.build.version.sdk'),
        ('model', '/system/bin/getprop ro.product.model'),
        ('version_before', f'/system/bin/pm list packages --show-versioncode --user {user} {package}'),
        ('paths_before', f'/system/bin/pm path --user {user} {package}'),
        ('version_after', f'/system/bin/pm list packages --show-versioncode --user {user} {package}'),
        ('paths_after', f'/system/bin/pm path --user {user} {package}'),
    ]
    parts = []
    for label, command in queries:
        parts.extend([f"printf '%s\\n' '{nonce}:{label}'", command])
    parts.append(f"printf '%s\\n' '{nonce}:end'")
    return ' && '.join(parts)


class Connection:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.sock.settimeout(remaining)

    def read(self, size):
        result = bytearray()
        while len(result) < size:
            self.remaining()
            part = self.sock.recv(size - len(result))
            require(bool(part))
            result.extend(part)
        return bytes(result)

    def send(self, data):
        self.remaining()
        self.sock.sendall(data)

    def service(self, value):
        data = value.encode('ascii')
        require(len(data) <= 65535)
        self.send(f'{len(data):04x}'.encode('ascii') + data)
        # Do not read or disclose a server's potentially sensitive FAIL text.
        require(self.read(4) == b'OKAY')

    def shell_output(self):
        self.send(struct.pack('<BI', 4, 0))  # shell-v2 close-stdin
        output = bytearray()
        for _ in range(MAX_FRAMES):
            channel, length = struct.unpack('<BI', self.read(5))
            require(length <= MAX_FRAME and len(output) + length <= MAX_OUTPUT)
            require(channel in (1, 3))  # any stderr/unknown channel refuses
            if channel == 3:
                require(length == 1 and self.read(1) == b'\x00')
                self.remaining()
                require(self.sock.recv(1) == b'')  # no duplicate exit/trailing payload
                return bytes(output)
            output.extend(self.read(length))
        raise Refused('frame_limit')


def collect(serial, package, user, port, timeout, nonce):
    validate(serial, package, user, port, timeout)
    script = commands(package, user, nonce)
    deadline = time.monotonic() + timeout
    # Literal IPv4 only: no DNS, subprocess, auto-start, reconnect or fallback.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        wire = Connection(sock, deadline)
        wire.remaining()
        sock.connect(('127.0.0.1', port))
        wire.service('host:transport:' + serial)
        # Same socket stays bound to this transport for the entire observation.
        wire.service('shell,v2,raw:' + script)
        return wire.shell_output()


def parse(raw, package, nonce):
    require(len(raw) <= MAX_OUTPUT)
    text = raw.decode('utf-8', errors='strict')
    require(not any(ord(c) < 32 and c not in '\n\r' for c in text))
    labels = ['release', 'api', 'model', 'version_before', 'paths_before', 'version_after', 'paths_after', 'end']
    sections = {}
    current = None
    seen = []
    for line in text.splitlines():
        if line.startswith(nonce + ':'):
            current = line[len(nonce) + 1:]
            require(len(seen) < len(labels) and current == labels[len(seen)])
            seen.append(current)
            sections[current] = []
        else:
            require(current is not None and current != 'end' and bool(line))
            sections[current].append(line)
    require(seen == labels)
    for key in ('release', 'api', 'model'):
        require(len(sections[key]) == 1)
    release, api, model = (sections[k][0] for k in ('release', 'api', 'model'))
    require(re.fullmatch(r'[0-9A-Za-z._-]{1,64}', release))
    require(re.fullmatch(r'[0-9]{1,3}', api) and 1 <= int(api) <= 999)
    require(0 < len(model.encode('utf-8')) <= 256)
    versions = []
    for key in ('version_before', 'version_after'):
        require(0 < len(sections[key]) <= 128)
        matches = []
        for line in sections[key]:
            row = re.fullmatch(r'package:([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+) versionCode:([0-9]{1,19})', line)
            require(row is not None)
            if row.group(1) == package:
                matches.append(int(row.group(2)))
        # pm's filter is substring-based. Never substitute a similarly named app.
        require(len(matches) == 1)
        versions.append(matches[0])
    require(versions[0] == versions[1])
    code = versions[0]
    require(code <= 0x7fffffffffffffff)
    before, after = sections['paths_before'], sections['paths_after']
    require(0 < len(before) <= MAX_APKS and len(before) == len(set(before)))
    require(sorted(before) == sorted(after) and len(after) == len(set(after)))
    for line in before:
        require(line.startswith('package:/') and line.endswith('.apk') and len(line) <= 4096)
        require(all(part and part not in ('.', '..') for part in line[len('package:/'):].split('/')))
    return {'android_release': release, 'android_api': int(api), 'model_sha256': digest(model),
            'version_code': code, 'apk_path_count': len(before),
            'apk_path_sha256': sorted(digest(line[len('package:'):]) for line in before),
            'matching_package_snapshots': True}


def inspect(serial, package, *, user=0, port=5037, timeout=10,
            authorized=False, trust_existing_server=False):
    started = time.monotonic()
    report = {'schema': 'vulcanary.android-readonly-inventory.v1', 'producer_version': __version__,
              'state': 'BLOCKED', 'collection_state': 'BLOCKED', 'reason': 'authorization_required',
              'finished_at': None, 'elapsed_seconds': None, 'observations': None,
              'device_selector_sha256': None, 'application_id_sha256': None, 'android_user': None,
              'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'evidence_method': 'existing-loopback-adb-shell-v2-metadata', 'policy_effect': 'none',
              'application_executed': False, 'independent_certification': False,
              'limits': {'output_bytes': MAX_OUTPUT, 'frames': MAX_FRAMES, 'frame_bytes': MAX_FRAME,
                         'apk_paths': MAX_APKS, 'timeout_seconds': None},
              'limitations': LIMITATIONS,
              'unverified': ['apk_bytes', 'signing', 'aab_lineage', 'version_name', 'runtime_behavior', 'security'],
              'action': 'Authorize one exact USB serial and package, trust an already-running local server, and use a supported metadata response. No server is started automatically.'}
    try:
        if authorized is not True or trust_existing_server is not True:
            return report
        validate(serial, package, user, port, timeout)
        report.update(device_selector_sha256=digest(serial), application_id_sha256=digest(package), android_user=user)
        report['limits']['timeout_seconds'] = timeout
        nonce = secrets.token_hex(16)
        raw = collect(serial, package, user, port, timeout, nonce)
        observed = parse(raw, package, nonce)
        report.update(state='NOT_RUN', collection_state='COMPLETE', reason='metadata_collected_security_not_run',
                      observations=observed,
                      action='Compare this limited observation with independent candidate evidence; authorize runtime tests separately.')
    except TimeoutError:
        report['reason'] = 'deadline_reached'
    except OSError:
        report['reason'] = 'connection_unavailable_or_interrupted'
    except (ValueError, UnicodeError, struct.error):
        report['reason'] = 'invalid_request_or_unsupported_response'
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return report


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output / 'report.json', report)
    with (output / 'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('# Android read-only inventory\n\n')
        stream.write(f"State: {report['state']}; collection: {report['collection_state']}; reason: {report['reason']}\n\n")
        stream.write(report['action'] + '\n\n')
        stream.write('\n'.join('- ' + s for s in report['limitations']) + '\n')
    write_new(output / 'checksums.json', {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                                        for name in ('report.json', 'reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--user', type=int, default=0)
    parser.add_argument('--server-port', type=int, default=5037)
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--authorize-read-only-inventory', action='store_true')
    parser.add_argument('--trust-existing-local-adb-server', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        require(not args.output.exists() and not args.output.is_symlink())
        report = inspect(args.serial, args.package, user=args.user, port=args.server_port, timeout=args.timeout,
                         authorized=args.authorize_read_only_inventory, trust_existing_server=args.trust_existing_local_adb_server)
        export(report, args.output)
        print(json.dumps({k: report[k] for k in ('state', 'collection_state', 'reason')}))
    except (OSError, ValueError):
        print('Android inventory blocked. Use an authorized scope and a new output directory.')
    return 2  # Inventory alone never means a successful security test.


if __name__ == '__main__':
    raise SystemExit(main())
