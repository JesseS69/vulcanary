"""Read-only, bounded single-base AAB declarations. No conversion or execution."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

from . import apk_inspection as apk, _android_proto as proto, _android_manifest as axml
from . import _android_resources as resources, _android_backup as backup
from .cli_errors import ArgumentParser

LIMITATIONS = [
    'Only a single base module is supported; feature modules, split merging and installed-device identity are not verified.',
    'AAPT2 protobuf XML and direct PROTO_XML resource links with one default configuration only; aliases, overlays, flags and configuration selection are unsupported.',
    'This is declaration inspection, not bundle validity, signing, build provenance, installability or runtime backup/restore verification.',
    'Explicit same-domain exact or whole-domain exclusions can pass; conditional sharedpref/database suffix expansions remain BLOCKED without device filesystem evidence.',
    'Missing explicit exclusions fail that declaration assertion, not a runtime privacy guarantee; ancestor, include-only and cross-domain protections are not inferred.',
    'BundleConfig, unrelated resource values and source-position metadata are not interpreted. Unsupported inspected message fields fail closed.',
    'No archive files are extracted, installed, converted or executed. No bundletool, Java, network or device access; no raw paths or resource strings in output.',
]


def declarations_and_links(archive, names, evaluate_rules, *, include_identity=False):
    axml.require('BundleConfig.pb' in names and 'AndroidManifest.xml' not in names)
    manifests = [name for name in names if name.endswith('/manifest/AndroidManifest.xml')]
    axml.require(manifests == ['base/manifest/AndroidManifest.xml'])
    # Reject any other module, including one lacking a manifest, instead of
    # reporting an incomplete base-only view as the bundle's declarations.
    axml.require(all(name.split('/')[0] in ('base', 'META-INF', 'BUNDLE-METADATA', 'BundleConfig.pb') for name in names))
    decoder = proto.Decoder()
    declarations = decoder.manifest(apk.read_member(archive, manifests[0], axml.MAX_XML), include_identity=include_identity)
    table = None
    if any(isinstance(v, dict) and v.get('kind') == 'reference' for v in declarations.values()):
        try:
            table = apk.read_member(archive, 'base/resources.pb', resources.MAX_TABLE)
        except (ValueError, KeyError, struct.error, zipfile.BadZipFile, zlib.error):
            pass
    links, parsed = [], {}
    for name in axml.BACKUP_ATTRIBUTES:
        row = {'attribute': name, 'resolution': 'not_declared', 'member_sha256': None, 'size_bytes': None}
        declaration = declarations.get(name)
        if declaration is not None:
            row['resolution'] = 'unresolved'
            if declaration['kind'] == 'boolean':
                row['resolution'] = 'literal_true' if declaration['value'] else 'literal_false'
            elif declaration['kind'] == 'reference' and table is not None:
                try:
                    path = decoder.resolve_xml(table, declaration['value'])
                    data = apk.read_member(archive, 'base/' + path, axml.MAX_XML)
                    row.update(resolution='resolved_file', member_sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
                    if evaluate_rules:
                        parsed[name] = decoder.backup_rules(data, name)
                except (ValueError, KeyError, struct.error, zipfile.BadZipFile, zlib.error):
                    pass
        links.append(row)
    return declarations, links, parsed


def inspect(path, *, backup_requirements=None):
    return apk.inspect(path, backup_requirements=backup_requirements, artifact_format='aab')


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--aab', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--backup-requirements', type=Path)
    try:
        args = parser.parse_args(argv)
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('existing_output')
        requested = backup.read_requirements(args.backup_requirements) if args.backup_requirements else None
        report = inspect(args.aab, backup_requirements=requested)
        apk.export(report, args.output)
        print(json.dumps({'state': report['state'], 'counts': report['counts'],
                          'backup_assertion_counts': report['backup_assertion_counts']}))
        return 0 if report['state'] == 'PASS' else 1 if report['state'] == 'FAIL' else 2
    except (OSError, ValueError, RecursionError):
        print('AAB inspection blocked. Supply a supported stable AAB and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
