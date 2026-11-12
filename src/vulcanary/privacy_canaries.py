"""Exact synthetic-canary searches of explicitly supplied files; no device access."""
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.parse import quote
import uuid

from .cli_errors import ArgumentParser
from .security_testing import read_document, write_new
from .version import __version__

MAX_BYTES = 8 * 1024 * 1024
MAX_MATCHES = 100
CATEGORIES = ('device-log', 'browser-log', 'crash-report', 'analytics-export',
              'url-capture', 'clipboard-export', 'temporary-file')


def create(path):
    marker = 'VULCANARY_TEST/' + secrets.token_urlsafe(24) + '+='
    record = {'schema': 'vulcanary.synthetic-canary.v1', 'id': str(uuid.uuid4()),
              'marker': marker, 'marker_sha256': hashlib.sha256(marker.encode()).hexdigest()}
    write_new(path, record)
    return record['id']


def load(path):
    record = read_document(path)
    if set(record) != {'schema', 'id', 'marker', 'marker_sha256'} or record['schema'] != 'vulcanary.synthetic-canary.v1':
        raise ValueError('invalid_canary')
    if not isinstance(record['id'], str):
        raise ValueError('invalid_canary_id')
    uuid.UUID(record['id'])
    marker = record['marker']
    if not isinstance(marker, str) or not re.fullmatch(r'VULCANARY_TEST/[A-Za-z0-9_-]{32}\+=', marker):
        raise ValueError('synthetic_marker_required')
    if record['marker_sha256'] != hashlib.sha256(marker.encode()).hexdigest():
        raise ValueError('changed_canary')
    return record


def base64_matches(data, raw):
    """Verify exact decoded bytes, including boundary groups, at each alignment."""
    for alignment in range(3):
        encoded = base64.b64encode(b'\x00' * alignment + raw)
        leading = 4 if alignment else 0
        trailing = 4 if (alignment + len(raw)) % 3 else 0
        core = encoded[leading:len(encoded) - trailing if trailing else len(encoded)]
        offset = 0
        while True:
            found = data.find(core, offset)
            if found < 0:
                break
            offset = found + 1
            start = found - leading
            if start < 0:
                continue
            window = data[start:start + len(encoded)]
            try:
                decoded = base64.b64decode(window, validate=True)
            except (ValueError, binascii.Error):
                continue
            if decoded[alignment:alignment + len(raw)] == raw:
                yield {'encoding': 'base64', 'byte_offset': start,
                       'decoded_offset_in_group': alignment}


def inspect_file(path, marker, index, category):
    result = {'file_id': index, 'category': category, 'state': 'BLOCKED',
              'sha256': None, 'size_bytes': None, 'coverage_complete': False,
              'matches': [], 'reason': 'unreadable_or_changed_input'}
    try:
        if path.is_symlink() or not path.is_file():
            return result
        with path.open('rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
                result['reason'] = 'input_limit_or_type'
                return result
            data = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        if path.is_symlink():
            return result
        current = path.stat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        path_signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if len(data) > MAX_BYTES or len(data) != before.st_size or signature(before) != signature(after) or path_signature(after) != path_signature(current):
            return result
        raw = marker.encode()
        patterns = {'literal': raw, 'hex': raw.hex().encode(),
                    'url-encoded': quote(marker, safe='').encode()}
        matches = []
        capped = False
        for encoding, pattern in patterns.items():
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset < 0:
                    break
                if len(matches) == MAX_MATCHES:
                    capped = True
                    break
                matches.append({'encoding': encoding, 'byte_offset': offset})
                offset += len(pattern)
            if capped:
                break
        if not capped:
            for match in base64_matches(data, raw):
                if len(matches) == MAX_MATCHES:
                    capped = True
                    break
                matches.append(match)
        result.update(state='FAIL' if matches else 'PASS', sha256=hashlib.sha256(data).hexdigest(),
                      size_bytes=len(data), coverage_complete=not capped, matches=matches,
                      reason='match_limit' if capped else 'exact_marker_detected' if matches else 'marker_not_observed')
    except OSError:
        pass
    return result


def scan(canary, paths, category, manifest_sha256, *, authorized=False):
    if not authorized:
        raise ValueError('authorization_required')
    if category not in CATEGORIES or not 1 <= len(paths) <= 16:
        raise ValueError('invalid_scope')
    if not re.fullmatch(r'[a-f0-9]{64}', manifest_sha256):
        raise ValueError('invalid_manifest_identity')
    record = load(canary)
    rows = [inspect_file(path, record['marker'], index, category) for index, path in enumerate(paths, 1)]
    counts = {state: sum(r['state'] == state for r in rows) for state in ('PASS', 'FAIL', 'BLOCKED')}
    state = 'FAIL' if counts['FAIL'] else 'BLOCKED' if counts['BLOCKED'] else 'PASS'
    return {'schema': 'vulcanary.privacy-canary-run.v1', 'producer_version': __version__,
            'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'run_id': str(uuid.uuid4()), 'finished_at': datetime.now(timezone.utc).isoformat(),
            'state': state, 'counts': counts, 'policy_effect': 'none', 'independent_certification': False,
            'manifest_sha256': manifest_sha256, 'candidate_binding': 'operator-declared-reference',
            'canary_id': record['id'], 'evidence_method': 'supplied-file-exact-canary-scan',
            'coverage_complete': all(r['coverage_complete'] for r in rows),
            'file_limit_bytes': MAX_BYTES, 'matches_limit': MAX_MATCHES, 'files': rows,
            'limitations': ['Only explicitly supplied synthetic exports were read; no device or clipboard was accessed.',
                            'No match is not proof of absence in unsupplied, truncated, transformed or untested surfaces.',
                            'Category and candidate binding are operator declarations, not verified collection provenance.',
                            'Literal, lowercase hex, contiguous standard base64 payloads at all byte alignments and uppercase percent-encoding are checked; wrapped base64 and other transformations may be missed.',
                            'Offsets identify positions in the hashed supplied files, without snippets or marker values.']}


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output / 'report.json', report)
    lines = ['# Synthetic privacy-canary scan', '', 'State: ' + report['state'], '',
             '| File ID | Category | State | Matches | Complete |', '|---|---|---|---|---|']
    lines += [f"| {r['file_id']} | {r['category']} | {r['state']} | {len(r['matches'])} | {r['coverage_complete']} |" for r in report['files']]
    lines += ['', ''] + ['- ' + item for item in report['limitations']]
    lines += ['', 'Checksums are unsigned, not authentication or independent certification.']
    with (output / 'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    write_new(output / 'checksums.json', {name: hashlib.sha256((output/name).read_bytes()).hexdigest() for name in ('report.json', 'reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    creation = commands.add_parser('create')
    creation.add_argument('--private-output', type=Path, required=True)
    search = commands.add_parser('scan')
    search.add_argument('--canary', type=Path, required=True)
    search.add_argument('--file', type=Path, action='append', required=True)
    search.add_argument('--category', choices=CATEGORIES, required=True)
    search.add_argument('--manifest-sha256', required=True)
    search.add_argument('--authorize-synthetic-exports', action='store_true')
    search.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == 'create':
            print(json.dumps({'state': 'NOT_RUN', 'canary_id': create(args.private_output)}))
            return 0
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('existing_output')
        report = scan(args.canary, args.file, args.category, args.manifest_sha256,
                      authorized=args.authorize_synthetic_exports)
        export(report, args.output)
        print(json.dumps({'state': report['state'], 'counts': report['counts']}))
        return 1 if report['counts']['FAIL'] else 2 if report['counts']['BLOCKED'] else 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('Privacy scan blocked. Supply a generated synthetic canary, bounded explicit files and a new output directory; no privacy guarantee is claimed.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
