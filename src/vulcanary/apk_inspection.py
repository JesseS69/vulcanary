"""Offline, bounded APK manifest declarations; no install, execution or extraction."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import uuid
import warnings
import zipfile
import zlib

from . import _android_manifest as axml
from . import _android_resources as resources
from .cli_errors import ArgumentParser
from .security_testing import write_new
from .test_inventory import MAX_ARTIFACT_BYTES
from .version import __version__

MAX_ENTRIES = 10000
MAX_DIRECTORY = 4 * 1024 * 1024


def directory_guard(stream, size):
    """Bound central-directory allocation before constructing ZipFile."""
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    offset = tail.rfind(b'PK\x05\x06')
    axml.require(offset >= 0 and offset + 22 <= len(tail))
    _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, comment = struct.unpack_from('<4s4H2IH', tail, offset)
    end_position = max(0, size - 65557) + offset
    axml.require(offset + 22 + comment == len(tail))
    axml.require(disk == cd_disk == 0 and disk_entries == entries and 0 < entries <= MAX_ENTRIES)
    axml.require(0 < cd_size <= MAX_DIRECTORY and cd_offset + cd_size == end_position)
    stream.seek(0)
    axml.require(stream.read(4) == b'PK\x03\x04')
    # ZIP64 is outside this bounded subset, including its alternate directory locator.
    stream.seek(max(0, end_position - 20))
    axml.require(stream.read(4) != b'PK\x06\x07')
    stream.seek(cd_offset)
    directory = stream.read(cd_size)
    cursor, actual_entries = 0, 0
    while cursor < len(directory):
        axml.require(actual_entries < MAX_ENTRIES and cursor + 46 <= len(directory))
        fields = struct.unpack_from('<4s6H3I5H2I', directory, cursor)
        axml.require(fields[0] == b'PK\x01\x02' and fields[13] == 0)
        axml.require(all(fields[index] != 0xffffffff for index in (8, 9, 16)))
        cursor += 46 + sum(fields[10:13])
        axml.require(cursor <= len(directory))
        actual_entries += 1
    axml.require(actual_entries == entries)
    return entries


def read_member(archive, name, limit):
    info = archive.getinfo(name)
    axml.require(not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16))
    axml.require(not info.flag_bits & 1 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
    axml.require(0 < info.file_size <= limit and 0 < info.compress_size <= limit)
    with warnings.catch_warnings():
        warnings.simplefilter('error', UserWarning)
        with archive.open(info) as member:
            data = member.read(limit + 1)
    axml.require(len(data) == info.file_size and len(data) <= limit)
    return data


def backup_links(archive, declarations):
    rows = []
    table = None
    if any(isinstance(declarations.get(name), dict) and declarations[name].get('kind') == 'reference'
           for name in axml.BACKUP_ATTRIBUTES):
        try:
            table = read_member(archive, 'resources.arsc', resources.MAX_TABLE)
        except (ValueError, KeyError, struct.error, zipfile.BadZipFile, zlib.error):
            pass
    for name in axml.BACKUP_ATTRIBUTES:
        declaration = declarations.get(name)
        row = {'attribute': name, 'resolution': 'not_declared', 'member_sha256': None, 'size_bytes': None}
        if declaration is not None:
            row['resolution'] = 'unresolved'
            if declaration['kind'] == 'boolean':
                row['resolution'] = 'literal_true' if declaration['value'] else 'literal_false'
            elif declaration['kind'] == 'reference' and table is not None:
                try:
                    path = resources.resolve_xml(table, declaration['value'])
                    data = read_member(archive, path, axml.MAX_XML)
                    row.update(resolution='resolved_file', member_sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
                except (ValueError, KeyError, struct.error, zipfile.BadZipFile, zlib.error):
                    pass
        rows.append(row)
    return rows


def read_artifact(path):
    axml.require(not path.is_symlink() and path.is_file())
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        axml.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_ARTIFACT_BYTES)
        checksum, total = hashlib.sha256(), 0
        while True:
            part = stream.read(min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - total))
            if not part:
                break
            checksum.update(part)
            total += len(part)
            axml.require(total <= MAX_ARTIFACT_BYTES)
        expected_entries = directory_guard(stream, total)
        with zipfile.ZipFile(stream) as archive:
            entries = archive.infolist()
            axml.require(len(entries) == expected_entries)
            names = [entry.filename for entry in entries]
            axml.require(len(set(names)) == len(names))
            axml.require(all(entry.orig_filename == entry.filename for entry in entries))
            data = read_member(archive, 'AndroidManifest.xml', axml.MAX_XML)
            declarations = axml.parse(data, include_backup=True)
            links = backup_links(archive, declarations)
        after = os.fstat(stream.fileno())
        axml.require(not path.is_symlink())
        current = path.stat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        path_signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        axml.require(signature(before) == signature(after) and path_signature(after) == path_signature(current))
        axml.require(total == before.st_size)
    return checksum.hexdigest(), total, declarations, links


def summarize(checks):
    counts = {state: sum(row['state'] == state for row in checks) for state in ('PASS', 'FAIL', 'BLOCKED')}
    if not checks or sum(counts.values()) != len(checks) or counts['BLOCKED']:
        state = 'BLOCKED'
    else:
        state = 'FAIL' if counts['FAIL'] else 'PASS'
    return state, counts


def inspect(path):
    checks = [{'id': name, 'state': 'BLOCKED', 'expected': False, 'observed': None,
               'basis': 'unavailable'} for name in ('debuggable', 'allowBackup')]
    checks.append({'id': 'backup-exclusions', 'state': 'BLOCKED', 'expected': 'verified_exclusions',
                   'observed': None, 'basis': 'resource_rules_not_evaluated'})
    report = {'schema': 'vulcanary.apk-manifest-inspection.v1', 'producer_version': __version__,
              'run_id': str(uuid.uuid4()), 'finished_at': datetime.now(timezone.utc).isoformat(),
              'state': 'BLOCKED', 'artifact_sha256': None, 'size_bytes': None,
              'evidence_method': 'packaged-binary-manifest', 'identity_verification': 'unavailable',
              'policy_effect': 'none', 'independent_certification': False, 'checks': checks, 'backup_resources': [],
              'reason': 'unsupported_invalid_or_changed_artifact',
              'action': 'Supply a stable APK with a supported binary manifest; unresolved backup rules require separate inspection.',
              'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes() + Path(axml.__file__).read_bytes() + Path(resources.__file__).read_bytes()).hexdigest(),
              'limits': {'artifact_bytes': MAX_ARTIFACT_BYTES, 'manifest_bytes': axml.MAX_XML,
                         'archive_entries': MAX_ENTRIES, 'central_directory_bytes': MAX_DIRECTORY,
                         'resource_table_bytes': resources.MAX_TABLE, 'backup_file_bytes': axml.MAX_XML},
              'limitations': ['Only packaged declarations are inspected; no signing, installability, installed-build identity or runtime behavior is verified.',
                              'Manifest defaults are Android documented defaults; boolean resource references remain unresolved rather than guessed.',
                              'Backup files are located and hashed only for unambiguous direct links; their contents, custom backup agents and device-specific behavior are not evaluated.',
                              'Aliases, sparse/compact resource entries, overlays and divergent configurations are outside resource-link coverage.',
                              'APK only: AAB/protobuf, split-set merging, ZIP64, text XML and unsupported binary chunks are blocked.',
                              'No archive contents are extracted, installed or executed. Output contains no package names, paths, raw strings or resource values.']}
    try:
        identity, size, declarations, links = read_artifact(path)
        for check in checks[:2]:
            name = check['id']
            observed = declarations.get(name, name == 'allowBackup')
            check.update(observed=observed, basis='typed_boolean' if name in declarations else 'android_default',
                         state='BLOCKED' if observed is None else 'FAIL' if observed else 'PASS')
            if observed is None:
                check['basis'] = 'unresolved_value'
        report.update(artifact_sha256=identity, size_bytes=size, identity_verification='local-bytes-hashed',
                      reason='declarations_inspected_with_coverage_gaps', backup_resources=links)
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, UserWarning):
        pass
    report['state'], report['counts'] = summarize(checks)
    # Incomplete coverage remains explicit even when a declaration fails.
    return report


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output/'report.json', report)
    lines = ['# APK manifest declaration inspection', '', 'State: ' + report['state'], '',
             'Artifact SHA-256: ' + (report['artifact_sha256'] or 'unavailable'), '']
    lines += [f"- {row['id']}: {row['state']}; observed={row['observed']}; basis={row['basis']}" for row in report['checks']]
    lines += ['', 'Backup resource links (not policy verdicts):']
    lines += [f"- {row['attribute']}: {row['resolution']}; SHA-256: {row['member_sha256'] or 'unavailable'}" for row in report['backup_resources']]
    lines += ['', report['action']] + ['- ' + value for value in report['limitations']]
    lines += ['', 'Checksums are unsigned, not authentication or independent certification.']
    with (output/'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    write_new(output/'checksums.json', {name: hashlib.sha256((output/name).read_bytes()).hexdigest() for name in ('report.json', 'reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('existing_output')
        report = inspect(args.apk)
        export(report, args.output)
        print(json.dumps({'state': report['state'], 'counts': report['counts']}))
        return 0 if report['state'] == 'PASS' else 1 if report['state'] == 'FAIL' else 2
    except (OSError, ValueError):
        print('APK inspection blocked. Supply a supported stable APK and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
