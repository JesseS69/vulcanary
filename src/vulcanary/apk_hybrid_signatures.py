"""Explicit SDK 37 hybrid-signature profile; separate from the classical contract."""
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import tempfile
import time

from . import _test_process as process
from .apk_inspection import summarize
from .apk_signatures import stable_copy
from .cli_errors import ArgumentParser
from .security_testing import write_new
from .version import __version__

MAX_APK = 256 * 1024 * 1024
MAX_TOOL = 32 * 1024 * 1024
HASH = re.compile(r'[a-f0-9]{64}\Z')
JVM = ['--enable-native-access=ALL-UNNAMED', '-Xms16m', '-Xmx64m', '-XX:MaxMetaspaceSize=64m',
       '-XX:CompressedClassSpaceSize=16m', '-XX:ReservedCodeCacheSize=16m',
       '-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC']
LIMITATIONS = [
    'PASS concerns only the stated signature, warning and operator-supplied signer checks, not application security or independent certification.',
    'Both hybrid role fingerprints must come from independently trusted release-certificate records; the fallback and source stamp cannot substitute for either role. Copying an observed signer into expectations is not verification.',
    'The approved artifact digest identifies input bytes, not their generation from an AAB or their release provenance.',
    'The Java executable and verifier JAR are hash-pinned; the installed Java runtime and its libraries must also be trusted. Hashes do not authenticate the distribution.',
    'A trusted external Java verifier executes with native access in a temporary directory. This is not an OS filesystem/network sandbox; APK code is not launched.',
    'Verification is restricted to one explicitly selected Android API level, not all platforms. Only API 37 with one hybrid pair plus a V3.0 fallback is supported; full rotation history and certificate ownership are not independently established.',
    'Source-stamp output is not treated as the application signing certificate or trusted distribution provenance.',
    'Warnings stay counted and require review; raw output, certificate names, filenames and exception text are not exported.',
    'Signing checks do not establish AAB lineage, split completeness, installed behavior, revocation status or cryptographic design security.',
]


def require(value):
    if not value:
        raise ValueError('refused')


def parse_verified(raw):
    require(len(raw) <= process.OUTPUT_LIMIT_BYTES)
    text = raw.decode('utf-8')
    require(not any(ord(c) < 32 and c not in '\r\n' for c in text))
    lines = [line for line in text.splitlines() if line]
    require(lines.count('Verifies') == 1 and lines.count('Number of signers: 1') == 1)
    schemes, certs, ranges, dev_releases, warnings = {}, {}, {}, {}, 0
    roles = {'V3.2 Hybrid Classical Signer': 'classical', 'V3.2 Hybrid PQC Signer': 'pqc',
             'V3.0 Signer': 'fallback'}
    metadata = re.compile(r'(?:certificate (?:DN|SHA-1 digest|MD5 digest)|key algorithm|key size \(bits\)|public key (?:SHA-256 digest|SHA-1 digest|MD5 digest)): .+')
    for line in lines:
        if line in ('Verifies', 'Number of signers: 1'):
            continue
        match = re.fullmatch(r'Verified using (v1|v2|v3|v3\.1|v3\.2|v4) scheme \([^\r\n]+\): (true|false)', line)
        if match:
            key, value = match.groups()
            require(key not in schemes)
            schemes[key] = value == 'true'
            continue
        if line.startswith('WARNING:'):
            warnings += 1
            continue
        if re.fullmatch(r'Verified for SourceStamp: (true|false)', line) or re.fullmatch(r'Source Stamp Timestamp: .+', line):
            continue
        if line.startswith('Source Stamp Signer: '):
            field = line[len('Source Stamp Signer: '):]
            require(metadata.fullmatch(field) or re.fullmatch(r'certificate SHA-256 digest: [a-fA-F0-9]{64}', field))
            continue
        matched = False
        for label, role in roles.items():
            if not line.startswith(label + ': '):
                continue
            matched = True
            field = line[len(label)+2:]
            if role != 'fallback':
                scoped = re.fullmatch(r'\(minSdkVersion=([0-9]{1,10})(?: \(dev release=(true|false)\))?, maxSdkVersion=([0-9]{1,10})\) (.+)', field)
                require(scoped is not None)
                low, high = int(scoped[1]), int(scoped[3])
                dev = scoped[2] == 'true'
                require(role not in dev_releases or dev_releases[role] == dev)
                dev_releases[role] = dev
                require(0 <= low <= 37 <= high <= 2147483647)
                require(role not in ranges or ranges[role] == [low, high])
                ranges[role] = [low, high]
                field = scoped[4]
            certificate = re.fullmatch(r'certificate SHA-256 digest: ([a-fA-F0-9]{64})', field)
            if certificate:
                require(role not in certs)
                certs[role] = certificate[1].lower()
            else:
                require(metadata.fullmatch(field) is not None)
            break
        require(matched)
    require(set(schemes) == {'v1','v2','v3','v3.1','v3.2','v4'} and schemes['v3.2'])
    require(set(certs) == {'classical','pqc','fallback'} and schemes['v3'])
    require(len(set(certs.values())) == 3 and ranges.get('classical') == ranges.get('pqc'))
    require(dev_releases.get('classical') == dev_releases.get('pqc'))
    return certs, ranges, dev_releases, schemes, warnings


def verify(artifact, artifact_sha256, java, java_sha256, jar, jar_sha256, *, android_api,
           expected_classical_sha256=None, expected_pqc_sha256=None, tool_version='0.9', authorized=False, timeout=30):
    started = time.monotonic()
    checks = [{'id': 'signature', 'state': 'BLOCKED', 'basis': 'not_verified'},
              {'id': 'expected_hybrid_signers', 'state': 'BLOCKED', 'basis': 'independent_expectation_missing'},
              {'id': 'warnings', 'state': 'BLOCKED', 'basis': 'not_evaluated'}]
    report = {'schema': 'vulcanary.apk-hybrid-signature-verification.v1', 'producer_version': __version__,
              'state': 'BLOCKED', 'reason': 'authorization_required', 'checks': checks,
              'artifact_sha256': None, 'size_bytes': None, 'android_api': None,
              'java_sha256': None, 'verifier_sha256': None, 'tool_version': None,
              'expected_signers': {'classical': None, 'pqc': None}, 'signers': None, 'signer_ranges': None, 'signer_dev_releases': None, 'schemes': None, 'warning_count': None,
              'attempted': False, 'application_executed': False, 'policy_effect': 'none',
              'independent_certification': False, 'cleanup': 'not_needed',
              'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes() + Path(process.__file__).read_bytes() + Path(stable_copy.__code__.co_filename).read_bytes()).hexdigest(),
              'limitations': LIMITATIONS, 'timeout_seconds': None, 'output_limit_bytes': process.OUTPUT_LIMIT_BYTES,
              'limits': {'artifact_bytes': MAX_APK, 'tool_bytes': MAX_TOOL, 'java_heap_mib': 64},
              'finished_at': None, 'elapsed_seconds': None,
              'action': 'Supply trusted pinned Java/SDK tools, approved APK bytes and an independent signer expectation. Review warnings separately; no runtime security is established.'}
    root = None
    try:
        if authorized is not True:
            return report
        report['reason'] = 'scope_refused'
        require(type(android_api) is int and android_api == 37)
        require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 120)
        require(isinstance(tool_version, str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,2}', tool_version))
        for expected in (expected_classical_sha256, expected_pqc_sha256):
            if expected is not None:
                require(isinstance(expected, str) and HASH.fullmatch(expected))
        require(expected_classical_sha256 is None or expected_pqc_sha256 is None or expected_classical_sha256 != expected_pqc_sha256)
        report.update(android_api=android_api, expected_signers={'classical': expected_classical_sha256, 'pqc': expected_pqc_sha256}, timeout_seconds=timeout)
        report['reason'] = 'tool_or_input_untrusted'
        stable_copy(java, None, java_sha256, MAX_TOOL)
        report['cleanup'] = 'unconfirmed'
        with tempfile.TemporaryDirectory(prefix='vulcanary-apk-signature-') as directory:
            root = Path(directory)
            stable_copy(jar, root / 'verifier.jar', jar_sha256, MAX_TOOL)
            size = stable_copy(artifact, root / 'artifact.apk', artifact_sha256, MAX_APK)
            report.update(artifact_sha256=artifact_sha256, size_bytes=size, java_sha256=java_sha256, verifier_sha256=jar_sha256)
            base = [str(java), *JVM, '-jar', str(root / 'verifier.jar')]
            deadline = time.monotonic() + timeout
            report.update(attempted=True, reason='tool_execution_failed')
            code, raw, forced = process.run_worker(base + ['version'], root, timeout)
            require(not forced and code == 0 and raw.decode('ascii').strip() == tool_version)
            report['tool_version'] = tool_version
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            command = base + ['verify', '--verbose', '--print-certs', '--min-sdk-version', str(android_api),
                              '--max-sdk-version', str(android_api), '--in', str(root / 'artifact.apk')]
            code, raw, forced = process.run_worker(command, root, remaining)
            # Confirm the isolated input and trusted launcher did not change during execution.
            stable_copy(root / 'artifact.apk', None, artifact_sha256, MAX_APK)
            stable_copy(root / 'verifier.jar', None, jar_sha256, MAX_TOOL)
            stable_copy(java, None, java_sha256, MAX_TOOL)
            if forced:
                report['reason'] = 'worker_limit_reached'
            elif code == 0:
                report['reason'] = 'unsupported_verifier_output'
                certs, ranges, dev_releases, schemes, warnings = parse_verified(raw)
                report.update(signers=certs, signer_ranges=ranges, signer_dev_releases=dev_releases, schemes=schemes, warning_count=warnings, reason='signature_verified_with_separate_trust_checks')
                checks[0].update(state='PASS', basis='sdk_verifier_accepts_for_selected_api')
                checks[2].update(state='BLOCKED' if warnings else 'PASS', basis='warnings_require_review' if warnings else 'no_warnings_reported')
                present = {role: value for role, value in report['expected_signers'].items() if value is not None}
                if any(certs[role] != value for role, value in present.items()):
                    checks[1].update(state='FAIL', basis='role_specific_expectation_mismatch')
                elif len(present) == 2:
                    checks[1].update(state='PASS', basis='both_role_specific_expectations_matched')
            elif code == 1 and b'DOES NOT VERIFY' in raw.splitlines():
                checks[0].update(state='FAIL', basis='sdk_verifier_rejected_input')
                report['reason'] = 'signature_verification_rejected'
            else:
                report['reason'] = 'unsupported_tool_failure'
        report['cleanup'] = 'complete'
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        pass
    finally:
        if root is not None and not root.exists():
            report['cleanup'] = 'complete'
        # A result is publishable only after the temporary execution area was removed.
        if report['cleanup'] == 'unconfirmed':
            for row in checks:
                row.update(state='BLOCKED', basis='execution_or_cleanup_unconfirmed')
            report.update(signers=None, signer_ranges=None, signer_dev_releases=None, schemes=None, warning_count=None)
        report['state'], report['counts'] = summarize(checks)
        report.update(finished_at=datetime.now(timezone.utc).isoformat(), elapsed_seconds=round(time.monotonic() - started, 3))
    return report


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output / 'report.json', report)
    with (output / 'reviewer.md').open('x', encoding='utf-8') as f:
        f.write('# APK signature checks\n\nState: ' + report['state'] + '\n\n')
        for row in report['checks']:
            f.write(f"- {row['id']}: {row['state']} ({row['basis']})\n")
        f.write('\n' + report['action'] + '\n\n' + '\n'.join('- ' + s for s in report['limitations']) + '\n')
    write_new(output / 'checksums.json', {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                                        for name in ('report.json', 'reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    for name in ('artifact', 'java', 'jar', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('artifact-sha256', 'java-sha256', 'jar-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--android-api', type=int, required=True)
    parser.add_argument('--expected-classical-sha256')
    parser.add_argument('--expected-pqc-sha256')
    parser.add_argument('--tool-version', default='0.9')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--authorize-trusted-verifier', action='store_true')
    try:
        args = parser.parse_args(argv)
        require(not args.output.exists() and not args.output.is_symlink())
        report = verify(args.artifact, args.artifact_sha256, args.java, args.java_sha256, args.jar, args.jar_sha256,
                        android_api=args.android_api, expected_classical_sha256=args.expected_classical_sha256, expected_pqc_sha256=args.expected_pqc_sha256,
                        tool_version=args.tool_version, authorized=args.authorize_trusted_verifier, timeout=args.timeout)
        export(report, args.output)
        print(json.dumps({'state': report['state'], 'checks': report['checks']}))
        return 0 if report['state'] == 'PASS' else 1 if report['state'] == 'FAIL' else 2
    except (OSError, ValueError):
        print('APK signature verification blocked. Supply pinned trusted tools, approved bytes and a new output directory.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
