"""Prepare offline device check instructions; never execute or attest a check."""
import hashlib
import json
from pathlib import Path

from .candidate_tests import load
from .cli_errors import ArgumentParser
from .security_testing import digest, write_new
from .version import __version__


# Fixed prose only: no operator-supplied strings are copied into the export.
CHECKS = (
    ('app-switcher', 'privacy-app-switcher',
     'Private synthetic content must not be readable in the app-switcher preview.',
     ['With separately authorized synthetic data, open a private screen.',
      'Enter the app switcher and observe the preview; repeat after returning to the app.',
      'Record whether private content was visible; do not capture real content.']),
    ('password-visibility', 'password-controls',
     'Password controls obscure the synthetic password by default and provide an understandable visibility toggle.',
     ['Use a disposable synthetic password on the approved test screen.',
      'Observe the initial masking and toggle visibility in both directions.',
      'Check that labels and focus remain understandable without recording the password.']),
    ('password-mismatch', 'password-controls',
     'Mismatched synthetic passwords cannot complete the operation and feedback is understandable.',
     ['On the approved isolated fixture, enter differing synthetic passwords.',
      'Attempt the permitted operation and observe refusal and feedback.',
      'Do not create, reset or change a real account.']),
    ('keyboard-open', 'keyboard-text-sizing',
     'Focused fields, error text and required actions remain reachable with the keyboard open.',
     ['On each approved input screen, focus the first and last fields.',
      'Observe scrolling, keyboard overlap and access to required actions.',
      'Dismiss and reopen the keyboard; check focus and content stability.']),
    ('text-sizing', 'keyboard-text-sizing',
     'At ordinary and largest supported text sizes, text remains readable and required actions reachable.',
     ['Only with separate settings-change authorization, record the initial text-size setting.',
      'Observe approved screens at ordinary and largest supported text sizes with keyboard open and closed.',
      'Check clipping, overlap, labels and reachable actions; restore the original setting.']),
    ('first-use', 'first-use-discoverability',
     'An uncoached participant can identify and complete the approved synthetic journey.',
     ['Agree on an isolated journey and stop conditions without explaining hidden controls.',
      'Ask the participant to attempt the journey; observe confusion and completion.',
      'Separate participant statements from observer conclusions.']),
)
LIMITATIONS = [
    'Instructions only: no device, app, endpoint, settings, files on a device or account is accessed.',
    'Preparation grants no permission to perform the described actions; execution requires separate scope and authorization.',
    'Candidate identity is operator-declared and is not verified against an installed app.',
    'No observation importer or attestation editor is provided; editing this file does not create verified evidence.',
    'This checklist does not satisfy any candidate requirement, including installed-device or human-observation evidence.',
    'Only selected manual journeys are described; omitted requirements are explicitly listed as unsupported here.',
    'No screenshots, secrets or free-form observations are collected. No independent certification is claimed.',
]


def prepare(manifest):
    doc = load(manifest)
    spec = doc['spec']
    if spec['candidate']['platform'] not in ('android', 'ios'):
        raise ValueError('unsupported_platform')
    rows = []
    for identifier, requirement, expected, steps in CHECKS:
        if requirement in spec['requirements']:
            rows.append({'id': identifier, 'requirement': requirement, 'state': 'NOT_RUN',
                         'executed': False, 'observed': None, 'expected': expected,
                         'planned_method': 'human_observation', 'steps': list(steps)})
    covered = {row['requirement'] for row in rows}
    return {
        'schema': 'vulcanary.guided-device-checklist.v1', 'producer_version': __version__,
        'state': 'NOT_RUN', 'executed': False, 'policy_effect': 'none',
        'independent_certification': False, 'identity_verification': 'operator-declared',
        'manifest_sha256': doc['manifest_sha256'], 'candidate_sha256': digest(spec['candidate']),
        'platform': spec['candidate']['platform'],
        'missing_identity_fields': sorted(k for k, v in spec['candidate'].items() if v is None),
        'implementation_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'checklist_sha256': digest(rows), 'checks': rows, 'evidence': [],
        'unsupported_requirements': sorted(set(spec['requirements']) - covered),
        'counts': {'PASS': 0, 'FAIL': 0, 'BLOCKED': 0, 'NOT_RUN': len(rows), 'DEFERRED': 0},
        'limitations': list(LIMITATIONS),
    }


def export(report, output):
    output.mkdir(exist_ok=False)
    write_new(output / 'report.json', report)
    lines = ['# Guided device checklist — NOT RUN', '',
             'No tests or observations have been performed. These instructions do not authorize device actions.',
             '', 'Candidate manifest digest: ' + report['manifest_sha256'],
             'Identity: operator-declared; not an installed-device verification.',
             'Missing identity fields: ' + (', '.join(report['missing_identity_fields']) or 'none declared missing'), '']
    for row in report['checks']:
        lines += ['## ' + row['id'] + ' — NOT_RUN', '', 'Expected: ' + row['expected'],
                  'Observed: none. Planned evidence: human observation.', '']
        lines += [f'{i}. {step}' for i, step in enumerate(row['steps'], 1)]
        lines += ['']
    lines += ['## Requirements not covered by this checklist', '']
    lines += ['- ' + item for item in report['unsupported_requirements']] or ['None requested outside this checklist.']
    lines += ['', '## Limits', ''] + ['- ' + item for item in report['limitations']]
    lines += ['', 'Checksums are unsigned integrity checks, not authentication or certification.']
    with (output / 'checklist.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    write_new(output / 'checksums.json', {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                                        for name in ('report.json', 'checklist.md')})


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        export(prepare(args.manifest), args.output)
        print(json.dumps({'state': 'NOT_RUN', 'executed': False}))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(json.dumps({'state': 'BLOCKED', 'code': 'checklist_refused',
                          'action': 'Use a valid registered mobile candidate and a new output directory.'}))
    return 2  # Successful preparation is never a successful test.


if __name__ == '__main__':
    raise SystemExit(main())
