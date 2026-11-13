"""Explicitly authorized, bounded copying of selected installed APK code files."""
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import stat
import struct
import time

from . import android_inventory as inv
from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 32
MAX_FRAMES = 131072
STAT = struct.Struct('<4sIQQIIIIQqqq')
LIMITATIONS = [
    'Copied bytes are observations from a trusted local ADB server and device, not authenticated build provenance or independent certification.',
    'No application launch, application-data read, key access, install, device write or server lifecycle operation is performed.',
    'Only freshly reported, approved /data/app code paths are supported. Other installation layouts are BLOCKED, never guessed.',
    'Component lstat checks reject observed symlinks and non-regular files but cannot make remote path lookup atomic. A hostile device can race or fabricate responses.',
    'Matching metadata/stat snapshots detect some changes, not change-and-revert races, an atomic snapshot or signing validity.',
    'Newly collected hashes identify observed bytes; copying them into expected records is not independent candidate verification.',
    'Collection remains NOT_RUN for security testing. Signing, AAB lineage, split completeness, backup effectiveness and runtime behavior are unverified.',
    'APK copies can contain private application code and packaged configuration. Keep the whole evidence directory private; reports omit raw device paths and selectors.',
    'Closing the client socket bounds collection, not proof that remote utility work terminated. Reports and checksums are unsigned.',
]


def request(wire, kind, path):
    inv.require(kind in (b'LST2', b'RECV'))
    raw = path.encode('ascii')
    inv.require(0 < len(raw) <= 1024)
    wire.send(struct.pack('<4sI', kind, len(raw)) + raw)


def lstat(wire, path):
    request(wire, b'LST2', path)
    inv.require(wire.read(4) == b'LST2')
    values = STAT.unpack(b'LST2' + wire.read(STAT.size - 4))
    inv.require(values[1] == 0)
    # Exclude access time: reading a file can legitimately change it.
    return values[2:9] + values[10:12]


def paths_from(raw, nonce, package):
    observed = inv.parse(raw, package, nonce)
    text = raw.decode('utf-8')
    lines = text.splitlines()
    start = lines.index(nonce + ':paths_before') + 1
    end = lines.index(nonce + ':version_after')
    paths = sorted(line[len('package:'):] for line in lines[start:end])
    inv.require(0 < len(paths) <= MAX_FILES)
    parents = set()
    for path in paths:
        inv.require(len(path.encode('utf-8')) <= 1024 and re.fullmatch(r'/data/app/[A-Za-z0-9_~+=./-]+', path))
        parts = PurePosixPath(path).parts
        inv.require(all(p not in ('.', '..', '') for p in path.split('/')[1:]))
        inv.require(5 <= len(parts) <= 7 and parts[-1].endswith('.apk'))
        parent = PurePosixPath(path).parent
        # Modern package directories have a package-name prefix plus random suffix.
        inv.require(parent.name.startswith(package + '-') and len(parent.name) > len(package) + 1)
        parents.add(str(parent))
        inv.require(parts[-1] == 'base.apk' or re.fullmatch(r'split_[A-Za-z0-9_.-]+\.apk', parts[-1]))
    inv.require(len(parents) == 1 and sum(PurePosixPath(p).name == 'base.apk' for p in paths) == 1)
    return observed, paths


def tree_stats(wire, paths):
    directories = set()
    for path in paths:
        directories.update(str(p) for p in PurePosixPath(path).parents if str(p) != '/')
    values = {}
    for path in sorted(directories, key=lambda p: (p.count('/'), p)):
        values[path] = lstat(wire, path)
        inv.require(stat.S_ISDIR(values[path][2]))
    total = 0
    for path in paths:
        values[path] = lstat(wire, path)
        mode, size = values[path][2], values[path][6]
        inv.require(stat.S_ISREG(mode) and 0 < size <= MAX_FILE)
        total += size
        inv.require(total <= MAX_TOTAL)
    return values


def receive(wire, remote, destination, size, owned=None):
    request(wire, b'RECV', remote)
    received = 0
    sha = hashlib.sha256()
    with destination.open('xb') as stream:
        if owned is not None:
            owned.append(destination)
        for _ in range(MAX_FRAMES):
            kind, length = struct.unpack('<4sI', wire.read(8))
            if kind == b'DONE':
                inv.require(length == 0 and received == size)
                return sha.hexdigest(), received
            inv.require(kind == b'DATA' and 0 < length <= 65536 and received + length <= size)
            chunk = wire.read(length)
            stream.write(chunk)
            sha.update(chunk)
            received += length
    raise inv.Refused('frame_limit')


def snapshot(serial, package, user, port, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    nonce = secrets.token_hex(16)
    raw = inv.collect(serial, package, user, port, min(remaining, 30), nonce)
    return paths_from(raw, nonce, package)


def check_expected(expected, serial, package, user):
    inv.require(isinstance(expected, dict) and expected.get('schema') == 'vulcanary.android-readonly-inventory.v1')
    inv.require(expected.get('collection_state') == 'COMPLETE' and expected.get('state') == 'NOT_RUN')
    inv.require(expected.get('device_selector_sha256') == inv.digest(serial))
    inv.require(expected.get('application_id_sha256') == inv.digest(package) and expected.get('android_user') == user)
    observed = expected.get('observations')
    inv.require(isinstance(observed, dict) and observed.get('matching_package_snapshots') is True)
    inv.require(type(observed.get('version_code')) is int and type(observed.get('apk_path_count')) is int)
    inv.require(0 < observed['apk_path_count'] <= MAX_FILES)
    pins = observed.get('apk_path_sha256')
    inv.require(isinstance(pins, list) and len(pins) == observed['apk_path_count'])
    inv.require(all(isinstance(p, str) and re.fullmatch('[a-f0-9]{64}', p) for p in pins))
    inv.require(len(set(pins)) == len(pins))
    return observed


def collect(serial, package, expected, output, *, user=0, port=5037, timeout=120,
            authorized=False, trust_existing_server=False):
    started = time.monotonic()
    report = {'schema': 'vulcanary.android-apk-collection.v1', 'producer_version': __version__,
              'state': 'BLOCKED', 'collection_state': 'BLOCKED', 'reason': 'authorization_required',
              'policy_effect': 'none', 'application_executed': False, 'independent_certification': False,
              'artifacts': [], 'observations': None, 'expected_inventory_sha256': None,
              'device_selector_sha256': None, 'application_id_sha256': None,
              'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes() + Path(inv.__file__).read_bytes()).hexdigest(),
              'finished_at': None, 'elapsed_seconds': None, 'cleanup_complete': True,
              'limits': {'file_bytes': MAX_FILE, 'total_bytes': MAX_TOTAL, 'files': MAX_FILES,
                         'data_frame_bytes': 65536, 'frames_per_file': MAX_FRAMES, 'timeout_seconds': None},
              'limitations': LIMITATIONS,
              'action': 'Authorize copying APK code files only, supply approved inventory and a new private output directory. Inspect copied bytes offline; do not infer runtime security.'}
    owned = []
    created = False
    try:
        if authorized is not True or trust_existing_server is not True:
            return report
        inv.validate(serial, package, user, port, min(timeout, 30))
        inv.require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 300)
        approved = check_expected(expected, serial, package, user)
        inv.require(isinstance(output, Path) and not output.exists() and not output.is_symlink())
        output.mkdir(exist_ok=False)
        created = True
        report.update(device_selector_sha256=inv.digest(serial), application_id_sha256=inv.digest(package),
                      expected_inventory_sha256=inv.digest(json.dumps(expected, sort_keys=True, separators=(',', ':'))))
        report['limits']['timeout_seconds'] = timeout
        deadline = started + timeout
        # Hold the selected sync transport open throughout both metadata snapshots.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            wire = inv.Connection(sock, deadline)
            wire.remaining()
            sock.connect(('127.0.0.1', port))
            wire.service('host:transport:' + serial)
            wire.service('sync:')
            before, paths = snapshot(serial, package, user, port, deadline)
            inv.require(before == approved)
            initial = tree_stats(wire, paths)
            artifacts = []
            for index, remote in enumerate(paths):
                local = output / f'artifact-{index:03d}.partial'
                sha, size = receive(wire, remote, local, initial[remote][6], owned)
                inv.require(lstat(wire, remote) == initial[remote])
                artifacts.append({'id': f'artifact-{index:03d}', 'role': 'base' if PurePosixPath(remote).name == 'base.apk' else 'split',
                                  'device_path_sha256': inv.digest(remote), 'sha256': sha, 'size_bytes': size})
            inv.require(tree_stats(wire, paths) == initial)
            after, final_paths = snapshot(serial, package, user, port, deadline)
            inv.require(after == before and final_paths == paths)
            # A trailing/forged transfer frame cannot be mistaken for another reply.
            inv.require(lstat(wire, paths[0]) == initial[paths[0]])
            wire.remaining()
        for index, path in enumerate(list(owned)):
            # Verify local bytes again before promoting the complete set.
            inv.require(not path.is_symlink() and path.is_file())
            sha = hashlib.sha256()
            read_bytes = 0
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(65536), b''):
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    sha.update(chunk)
                    read_bytes += len(chunk)
                    inv.require(read_bytes <= artifacts[index]['size_bytes'])
            inv.require(sha.hexdigest() == artifacts[index]['sha256'] and path.stat().st_size == artifacts[index]['size_bytes'])
            destination = path.with_suffix('.apk')
            inv.require(not destination.exists() and not destination.is_symlink())
            # Exclusive promotion: unlike POSIX rename, this cannot replace a file.
            destination.hardlink_to(path)
            owned.append(destination)
            path.unlink()
        report.update(state='NOT_RUN', collection_state='COMPLETE', reason='apk_bytes_collected_security_not_run',
                      artifacts=artifacts, observations=before)
    except TimeoutError:
        report['reason'] = 'deadline_reached'
    except OSError:
        report['reason'] = 'connection_or_storage_unavailable'
    except (ValueError, TypeError, UnicodeError, struct.error):
        report['reason'] = 'scope_or_response_refused'
    finally:
        if report['collection_state'] != 'COMPLETE':
            for path in owned:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    report['cleanup_complete'] = False
        report.update(finished_at=datetime.now(timezone.utc).isoformat(), elapsed_seconds=round(time.monotonic() - started, 3))
        if created:
            write_new(output / 'report.json', report)
            with (output / 'reviewer.md').open('x', encoding='utf-8') as stream:
                stream.write('# Installed APK code-file collection\n\n')
                stream.write(f"State: {report['state']}; collection: {report['collection_state']}; reason: {report['reason']}\n\n")
                for artifact in report['artifacts']:
                    stream.write(f"- {artifact['id']} ({artifact['role']}): {artifact['size_bytes']} bytes; SHA-256 {artifact['sha256']}\n")
                stream.write('\n' + report['action'] + '\n\n')
                stream.write('\n'.join('- ' + item for item in report['limitations']) + '\n')
            write_new(output / 'checksums.json', {'report.json': hashlib.sha256((output / 'report.json').read_bytes()).hexdigest(),
                                                 'reviewer.md': hashlib.sha256((output / 'reviewer.md').read_bytes()).hexdigest(),
                                                 **{a['id'] + '.apk': a['sha256'] for a in report['artifacts']}})
    return report


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--user', type=int, default=0)
    parser.add_argument('--server-port', type=int, default=5037)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--authorize-apk-code-copy', action='store_true')
    parser.add_argument('--trust-existing-local-adb-server', action='store_true')
    try:
        args = parser.parse_args(argv)
        with args.inventory.open('rb') as stream:
            raw = stream.read(32769)
        inv.require(len(raw) <= 32768)
        def unique(pairs):
            value = {}
            for key, item in pairs:
                inv.require(key not in value)
                value[key] = item
            return value
        report = collect(args.serial, args.package, json.loads(raw, object_pairs_hook=unique), args.output, user=args.user,
                         port=args.server_port, timeout=args.timeout, authorized=args.authorize_apk_code_copy,
                         trust_existing_server=args.trust_existing_local_adb_server)
        print(json.dumps({k: report[k] for k in ('state', 'collection_state', 'reason')}))
    except (OSError, ValueError, RecursionError):
        print('APK collection blocked. Supply an authorized scope, approved inventory and new private output directory.')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
