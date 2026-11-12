"""Frozen candidate contracts and honestly scoped bundled transfer-model evidence."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

from .cli_errors import ArgumentParser
from .security_testing import digest, read_document, write_new
from .transfer_model import run_scenarios, SCENARIOS
from .version import __version__


# These are methods, not a ranking. One method cannot substitute for another.
METHODS = {'source', 'mock', 'local_database', 'real_transport', 'installed_device',
           'browser', 'human_observation', 'user_report', 'artifact_inspection'}
REQUIREMENTS = {
    'model-transfer-contract': ('mock',),
    'transfer-refusal': ('real_transport', 'installed_device'),
    'transfer-upload-response-loss': ('real_transport', 'installed_device'),
    'transfer-completion-response-loss': ('real_transport', 'installed_device'),
    'transfer-account-switch': ('installed_device',),
    'transfer-historical-keys': ('installed_device',),
    'transfer-source-preserved': ('installed_device',),
    'transfer-cancel-expire-replay': ('real_transport', 'installed_device'),
    'transfer-concurrent-receivers': ('local_database', 'real_transport'),
    'transfer-durable-receipt': ('installed_device',),
    'database-authorization': ('local_database',),
    'database-concurrency': ('local_database',),
    'native-termination-restart': ('installed_device',),
    'native-storage-rollback': ('installed_device',),
    'native-full-storage': ('installed_device',),
    'privacy-device-logs': ('installed_device',),
    'privacy-browser-logs': ('browser',),
    'privacy-crash-analytics-urls': ('real_transport', 'installed_device'),
    'privacy-clipboard': ('installed_device',),
    'privacy-app-switcher': ('installed_device', 'human_observation'),
    'privacy-temporary-files': ('installed_device',),
    'privacy-media-cache': ('installed_device',),
    'artifact-backup-exclusions': ('artifact_inspection',),
    'artifact-debug-flags': ('artifact_inspection',),
    'signup-email-links-cold-warm': ('installed_device',),
    'password-controls': ('installed_device', 'human_observation'),
    'keyboard-text-sizing': ('installed_device', 'human_observation'),
    'follow-block-notifications': ('installed_device',),
    'post-comment-reactions': ('installed_device',),
    'chat-flare-media': ('installed_device',),
    'account-isolation': ('real_transport', 'installed_device'),
    'first-use-discoverability': ('human_observation',),
    'web-isolated-contexts': ('browser',),
    'web-storage-console-network': ('browser',),
    'performance-repeated-samples': ('installed_device',),
    'media-near-limit-codecs': ('installed_device', 'human_observation'),
    'ios-device-coverage': ('installed_device',),
}
LIMITATIONS = [
    'Bundled reference model only: no Zirze or other application code executed.',
    'SQLite transactions are harness state, not evidence of deployed database behavior or RLS.',
    'Response loss is a simulated outcome, not an HTTP socket failure.',
    'Restart means SQLite close/reopen, not native process termination.',
    'Storage faults are injected exceptions, not physical full-storage or native filesystem tests.',
    'Opaque synthetic key values and equality checks are not encryption/decryption or cryptographic proof.',
    'Candidate and scope fields are operator declarations; installed identity is not independently verified.',
    'No endpoint, device, account credential, application command or production environment is contacted.',
]


def token(value, nullable=False):
    return (nullable and value is None) or (isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value) is not None)


def hash_value(value, length=64, nullable=False):
    return (nullable and value is None) or (isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is not None)


def validate(spec):
    if not isinstance(spec, dict) or set(spec) != {'candidate', 'scope', 'requirements'}:
        raise ValueError('invalid_manifest')
    c = spec['candidate']
    fields = {'platform', 'source_commit', 'artifact_sha256', 'installed_version', 'os_version', 'device_sha256', 'environment_sha256', 'account_roles', 'transfer_eligibility'}
    if not isinstance(c, dict) or set(c) != fields:
        raise ValueError('invalid_candidate')
    if c['platform'] not in ('android', 'ios', 'web', 'synthetic-model'):
        raise ValueError('invalid_platform')
    if not hash_value(c['source_commit'], 40, True) or not hash_value(c['artifact_sha256'], nullable=True):
        raise ValueError('invalid_identity')
    if not token(c['installed_version'], True) or not token(c['os_version'], True):
        raise ValueError('invalid_version')
    if not hash_value(c['device_sha256'], nullable=True) or not hash_value(c['environment_sha256']):
        raise ValueError('invalid_environment')
    roles = c['account_roles']
    if not isinstance(roles, list) or not 1 <= len(roles) <= 8:
        raise ValueError('invalid_roles')
    seen = set()
    for role in roles:
        if not isinstance(role, dict) or set(role) != {'role', 'identity_sha256'} or role['role'] not in ('source', 'receiver', 'outsider') or not hash_value(role['identity_sha256']):
            raise ValueError('invalid_role')
        key = (role['role'], role['identity_sha256'])
        if key in seen:
            raise ValueError('duplicate_role')
        seen.add(key)
    if c['transfer_eligibility'] not in ('enabled', 'disabled', 'unknown'):
        raise ValueError('invalid_eligibility')
    scope = spec['scope']
    if not isinstance(scope, dict) or set(scope) != {'environment', 'synthetic_data', 'permitted_actions'}:
        raise ValueError('invalid_scope')
    if scope['environment'] not in ('local-synthetic', 'staging') or scope['synthetic_data'] is not True:
        raise ValueError('unsupported_scope')
    actions = scope['permitted_actions']
    if not isinstance(actions, list) or any(a not in ('register', 'run-bundled-transfer-model') for a in actions) or len(actions) != len(set(actions)) or 'register' not in actions:
        raise ValueError('unsupported_action')
    required = spec['requirements']
    if not isinstance(required, list) or not required or any(not isinstance(r, str) or r not in REQUIREMENTS for r in required) or len(required) != len(set(required)):
        raise ValueError('invalid_requirements')


def register(spec_path, output):
    spec = read_document(spec_path)
    validate(spec)
    document = {'schema': 'vulcanary.candidate-manifest.v1', 'manifest_sha256': digest(spec), 'spec': spec}
    write_new(output, document)
    return document


def load(path):
    doc = read_document(path)
    if set(doc) != {'schema', 'manifest_sha256', 'spec'} or doc['schema'] != 'vulcanary.candidate-manifest.v1':
        raise ValueError('invalid_registration')
    validate(doc['spec'])
    if doc['manifest_sha256'] != digest(doc['spec']):
        raise ValueError('changed_manifest')
    return doc


def assess(requirement, manifest_hash, evidence):
    """Internal receipt assessment; not an importer for arbitrary PASS documents."""
    matched = [e for e in evidence if e['requirement'] == requirement and e['manifest_sha256'] == manifest_hash]
    required = set(REQUIREMENTS[requirement])
    relevant = [e for e in matched if e['method'] in required]
    if any(e['state'] == 'FAIL' for e in relevant):
        return 'FAIL'  # A later PASS never erases a failure within this report.
    if any(e['state'] == 'BLOCKED' for e in relevant):
        return 'BLOCKED'
    if required <= {e['method'] for e in relevant if e['state'] == 'PASS'}:
        return 'PASS'
    return 'NOT_RUN'


def execute(path, *, authorized=False):
    started = datetime.now(timezone.utc).isoformat()
    doc = load(path)
    spec, identity = doc['spec'], doc['manifest_sha256']
    rows, evidence, scenarios = [], [], []
    allowed = authorized and 'run-bundled-transfer-model' in spec['scope']['permitted_actions']
    if allowed:
        scenarios = run_scenarios()
        complete = (len(scenarios) == len(SCENARIOS) and
                    {r['scenario'] for r in scenarios} == set(SCENARIOS) and
                    all(r['state'] in ('PASS', 'FAIL') and r['cleanup'] == 'complete' for r in scenarios))
        state = 'BLOCKED' if not complete else 'FAIL' if any(r['state'] == 'FAIL' for r in scenarios) else 'PASS'
        # Only a synthetic-model subject can receive a model-contract PASS.
        if spec['candidate']['platform'] == 'synthetic-model':
            evidence.append({'requirement': 'model-transfer-contract', 'manifest_sha256': identity,
                             'method': 'mock', 'state': state})
    for requirement in spec['requirements']:
        state = assess(requirement, identity, evidence)
        if state == 'NOT_RUN':
            state = 'BLOCKED' if requirement != 'model-transfer-contract' or not allowed else 'NOT_RUN'
        rows.append({'id': requirement, 'state': state, 'required_methods': list(REQUIREMENTS[requirement]),
                     'reason': 'model_assertions_only' if state in ('PASS', 'FAIL') else 'adapter_or_authorization_unavailable',
                     'action': 'Review synthetic scenario evidence.' if state in ('PASS', 'FAIL') else 'Provide a separately authorized adapter and evidence for this exact candidate; do not substitute model results.'})
    counts = {state: sum(r['state'] == state for r in rows) for state in ('PASS', 'FAIL', 'BLOCKED', 'NOT_RUN', 'DEFERRED')}
    state = next(s for s in ('FAIL', 'BLOCKED', 'NOT_RUN', 'DEFERRED', 'PASS') if counts[s])
    return {'schema': 'vulcanary.candidate-test-run.v1', 'producer_version': __version__,
            'run_id': str(uuid.uuid4()), 'finished_at': datetime.now(timezone.utc).isoformat(),
            'started_at': started, 'python_version': '.'.join(map(str, sys.version_info[:3])),
            'candidate': spec['candidate'], 'declared_scope': spec['scope'],
            'manifest_sha256': identity, 'candidate_sha256': digest(spec['candidate']),
            'identity_verification': 'operator-declared', 'state': state, 'counts': counts,
            'policy_effect': 'none', 'independent_certification': False,
            'adapter': 'bundled-transfer-reference.v1',
            'implementation_sha256': digest({name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ('candidate_tests.py', 'transfer_model.py')}),
            'requirements': rows, 'evidence': evidence, 'synthetic_scenarios': scenarios,
            'reproduction': ['python', '-m', 'vulcanary.candidate_tests', 'run', '--manifest',
                             'PRIVATE_MANIFEST', '--authorize-bundled-model', '--output', 'NEW_DIRECTORY'],
            'limitations': LIMITATIONS}


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output / 'report.json', report)
    lines = ['# Candidate testing report', '', 'Overall: ' + report['state'],
             '', 'Identity: operator-declared; digest ' + report['manifest_sha256'],
             '', '## Requirements', '', '| Requirement | State | Required evidence |', '|---|---|---|']
    lines += [f"| {r['id']} | {r['state']} | {', '.join(r['required_methods'])} |" for r in report['requirements']]
    lines += ['', '## Bundled model observations (not application results)', '']
    lines += [f"- {r['scenario']}: {r['state']}" for r in report['synthetic_scenarios']]
    lines += ['', '## Limits', ''] + ['- ' + item for item in LIMITATIONS]
    lines += ['', 'Checksums are unsigned; they do not authenticate authorship or certify security.']
    with (output / 'reviewer.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    write_new(output / 'checksums.json', {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in ('report.json', 'reviewer.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    registration = commands.add_parser('register')
    registration.add_argument('--spec', type=Path, required=True)
    registration.add_argument('--output', type=Path, required=True)
    run = commands.add_parser('run')
    run.add_argument('--manifest', type=Path, required=True)
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--authorize-bundled-model', action='store_true')
    try:
        args = parser.parse_args(argv)
        if args.command == 'register':
            doc = register(args.spec, args.output)
            print(json.dumps({'state': 'NOT_RUN', 'manifest_sha256': doc['manifest_sha256']}))
            return 0
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('existing_output')
        report = execute(args.manifest, authorized=args.authorize_bundled_model)
        export(report, args.output)
        print(json.dumps({'state': report['state'], 'counts': report['counts']}))
        return 1 if report['counts']['FAIL'] else 0 if report['state'] == 'PASS' else 2
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('Candidate test blocked. Check the bounded manifest, allowed scope and new output path; no completion is claimed.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
