"""Offline Android artifact/manifest identity assertions, never installed identity."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid
import zipfile
import zlib

from . import apk_inspection as apk, aab_inspection as aab
from . import _android_manifest as axml, _android_proto as proto
from . import _android_resources as resources, _android_backup as backup
from . import _android_identity_fields as fields
from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

MAX_EXPECTED_BYTES = 16384
KEYS = {'schema', 'artifact_format', 'artifact_sha256', 'application_id', 'version_code', 'version_name'}
LIMITATIONS = [
    'PASS means these local bytes and packaged declarations match an operator-supplied record, not a security verdict or independent certification.',
    'Expected values must come from an independent candidate record; copying observed values into expectations is not meaningful verification.',
    'Neither matching versions nor matching application identifiers proves an APK was generated from an AAB. Generation lineage and signing are not verified.',
    'No installed device, split-set completeness, OS, account, environment, backup/restore or application behavior is verified.',
    'AAB evidence describes input to device-specific APK generation, not generated APKs or what reached a phone.',
    'Only direct packaged identity values are supported. Missing or resource-referenced values remain BLOCKED; absent versionCodeMajor defaults to zero.',
    'Application identifier and version name are hashed in reports. Hashes are not encryption, authentication or secrecy for guessable values.',
    'Artifact parsing reuses bounded APK/AAB guards; no extraction, conversion, tool launch, network or target execution.',
]


def validate_expected(value):
    axml.require(isinstance(value, dict) and set(value) == KEYS)
    axml.require(value['schema'] == 'vulcanary.android-identity-expectations.v1')
    axml.require(value['artifact_format'] in ('apk', 'aab'))
    axml.require(isinstance(value['artifact_sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['artifact_sha256']))
    for key in ('application_id', 'version_name'):
        text = value[key]
        axml.require(isinstance(text, str) and 0 < len(text.encode('utf-8')) <= 1024 and not any(ord(c) < 32 for c in text))
    axml.require(type(value['version_code']) is int and 0 <= value['version_code'] <= 0x7fffffff7fffffff)
    axml.require(value['version_code'] & 0xffffffff <= 0x7fffffff)
    return value


def read_expected(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            axml.require(key not in result)
            result[key] = value
        return result
    axml.require(not path.is_symlink())
    with path.open('rb') as stream:
        raw = stream.read(MAX_EXPECTED_BYTES + 1)
    axml.require(len(raw) <= MAX_EXPECTED_BYTES)
    return validate_expected(json.loads(raw.decode('utf-8'), object_pairs_hook=unique))


def text_hash(value):
    return None if value is None else hashlib.sha256(value.encode('utf-8')).hexdigest()


def inspect(path, expected):
    expected = validate_expected(expected)
    wanted = {'artifact_sha256': expected['artifact_sha256'],
              'application_id_sha256': text_hash(expected['application_id']),
              'version_code': expected['version_code'], 'version_name_sha256': text_hash(expected['version_name'])}
    checks = [{'id': name, 'state': 'BLOCKED', 'expected': value, 'observed': None,
               'basis': 'identity_unavailable'} for name, value in wanted.items()]
    modules = (apk, aab, axml, proto, resources, backup, fields)
    implementation = hashlib.sha256(Path(__file__).read_bytes() + b''.join(Path(m.__file__).read_bytes() for m in modules)).hexdigest()
    report = {'schema': 'vulcanary.android-artifact-identity.v1', 'producer_version': __version__,
              'run_id': str(uuid.uuid4()), 'finished_at': datetime.now(timezone.utc).isoformat(),
              'artifact_format': expected['artifact_format'], 'artifact_sha256': None, 'size_bytes': None,
              'expectations_sha256': backup.digest(expected), 'implementation_sha256': implementation,
              'evidence_method': 'local-bytes-and-packaged-manifest', 'policy_effect': 'none',
              'independent_certification': False, 'target_executed': False, 'checks': checks,
              'limitations': LIMITATIONS,
              'unverified': ['generation_lineage', 'signing', 'installed_identity', 'runtime_behavior'],
              'limits': {'expected_bytes': MAX_EXPECTED_BYTES, 'artifact_bytes': apk.MAX_ARTIFACT_BYTES,
                         'archive_entries': apk.MAX_ENTRIES, 'central_directory_bytes': apk.MAX_DIRECTORY,
                         'manifest_bytes': axml.MAX_XML, 'resource_table_bytes': resources.MAX_TABLE,
                         'protobuf_fields': proto.MAX_FIELDS, 'protobuf_nodes': proto.MAX_NODES,
                         'protobuf_depth': proto.MAX_DEPTH, 'protobuf_decoded_text_bytes': proto.MAX_TEXT},
              'action': 'Supply a stable supported artifact and independent expected identity values; no installed-device evidence is claimed.'}
    try:
        digest, size, declarations, _, _ = apk.read_artifact(path, artifact_format=expected['artifact_format'], include_identity=True)
        identity = declarations['_identity']
        observed = {'artifact_sha256': digest, 'application_id_sha256': text_hash(identity['application_id']),
                    'version_code': identity['version_code'], 'version_name_sha256': text_hash(identity['version_name'])}
        report.update(artifact_sha256=digest, size_bytes=size)
        for row in checks:
            value = observed[row['id']]
            row['observed'] = value
            if value is not None:
                row.update(state='PASS' if value == row['expected'] else 'FAIL',
                           basis='expected_identity_matched' if value == row['expected'] else 'expected_identity_mismatch')
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, UserWarning):
        pass
    report['state'], report['counts'] = apk.summarize(checks)
    return report


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output/'report.json', report)
    lines = ['# Android artifact identity assertions', '', 'State: ' + report['state'], '',
             'PASS verifies only a match to the supplied record, not the application or installed device.', '']
    lines += [f"- {r['id']}: {r['state']}; expected={r['expected']}; observed={r['observed']}; basis={r['basis']}" for r in report['checks']]
    lines += ['', report['action'], ''] + ['- '+text for text in report['limitations']]
    with (output/'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines)+'\n')
    write_new(output/'checksums.json', {name: hashlib.sha256((output/name).read_bytes()).hexdigest() for name in ('report.json','reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--expected', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        axml.require(not args.output.exists() and not args.output.is_symlink())
        report = inspect(args.artifact, read_expected(args.expected))
        export(report, args.output)
        print(json.dumps({'state': report['state'], 'counts': report['counts']}))
        return 0 if report['state'] == 'PASS' else 1 if report['state'] == 'FAIL' else 2
    except (OSError, ValueError, RecursionError):
        print('Android identity check blocked. Supply bounded independent expectations and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
