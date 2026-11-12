# Frozen candidate testing and transfer-model acceptance

This work translates the encrypted mobile/web testing brief into a reusable
platform contract. It is not an implementation of a particular application's
bug backlog. The current milestone is **synthetic reference-model evidence**,
not a passing test of an installed application.

## Run a complete coverage report

```text
python -m vulcanary.candidate_tests register --spec examples/security-testing/candidate-model.json --output private-manifest.json
python -m vulcanary.candidate_tests run --manifest private-manifest.json --authorize-bundled-model --output new-reviewer-package
```

Registration is NOT_RUN. The supplied full-brief example deliberately returns
BLOCKED (exit 2): the one reference-model contract passes while 36 application
requirements remain blocked. The report preserves all of them rather than calling
the candidate clean. PASS/FAIL here describe assertions, not security certification.
For execution, exit 0 requires PASS, exit 1 indicates a failed requirement, and
BLOCKED, NOT_RUN or DEFERRED exits 2. Registration alone still exits 0 when the
manifest was successfully created; its NOT_RUN state is not execution evidence. Run reports remain
outside scanner policy, severity counts, SLA and remediation.

The manifest freezes source commit, artifact hash, installed version, OS version,
device/environment identifiers (hashes), synthetic account-role identifiers and
transfer eligibility. Null fields explicitly mean unknown; registration does not
verify an installed artifact. The entire candidate, scope and requirement list
contribute to its digest. Altering any field without re-registering is refused.
These hashes are unsigned identity checks, not proof of authorship or authorization.
Retain the private registered manifest for reproduction.

Only local-synthetic/staging declarations and synthetic data are accepted. Allowed
actions are registration and the bundled model. A staging declaration does not
authorize network access: there are no endpoints or device commands in this format.
Credentials, arbitrary commands, extra fields and production declarations are
rejected. No application source, database, account or device is accessed.

## Evidence methods cannot substitute for each other

Source inspection, mocks, local database tests, real transport, installed-device
checks, browser checks, human observations, user reports and artifact inspection
are distinct methods, not a ranking. Requirements needing two methods need both.
Evidence must match the exact frozen manifest and requirement. FAIL stays FAIL even
if a later matching attempt passes. Wrong-candidate evidence cannot close a check.

The receipt assessor is an internal contract, not a public importer for arbitrary
PASS claims. This command produces only mock receipts, only for a synthetic-model
candidate. Registering an Android/iOS/web candidate cannot convert model success
into application evidence. Native/device/database receipts are not manufactured.
DEFERRED is reserved in the result vocabulary; this first command provides no
operator deferral or manual attestation editor.

## What the transfer harness actually does

The bundled reference model uses a disposable SQLite database and locally generated
opaque synthetic values representing two historical key versions. It checks:

- approval/refusal and a request rejected before simulated upload;
- upload commit followed by simulated response loss, retry without a second export;
- completion commit followed by simulated response loss and safe retry;
- stale-account installation rejection;
- atomic rollback after injected partial-write, storage-failure and read-back faults;
- receipt preservation across database close/reopen, duplicate-install rejection;
- cancellation/expiry before claim and a second sequential receiver being refused;
- preservation of the source values and receiver equality with both versions.

Each scenario has its own database and cleanup. All 16 must complete before the
model contract can pass. Uncertain responses and interrupted attempts remain in
the event trace after retries. Output includes only fixed scenario/operation names,
states and outcomes, never key values or raw exceptions. Export paths must be new;
the JSON and concise Markdown have unsigned checksums. Missing final checksums
indicate an incomplete package.

Tests deliberately break authorization, account checks, atomicity, duplicate
handling, re-export prevention and source preservation. The appropriate scenario
must fail for each broken model. This demonstrates that the assertions discriminate;
it does not show an external app uses this implementation.

There is no encryption/decryption, socket transport, deployed SQL/RLS, concurrent
claim race or native process death in this harness. SQLite reopen is not native
relaunch. Injected storage exceptions are not physical disk exhaustion. Sequential
receiver checks are not concurrency evidence. These limits appear in every report.

## Remaining work from the brief

| Area | Current support | Required next evidence |
|---|---|---|
| Frozen candidate/scope | Bounded declarations and digest binding | Independently inspect installed build/device and endpoint identity |
| Transfer/recovery | 16 reference-model scenarios and six negative controls | Authorized application adapter; text/photo history and real keys in disposable fixtures |
| Transport failures | Simulated commit/response separation | Owned local HTTP socket harness, then separately authorized staging transport |
| Database authorization/concurrency | Harness-only SQLite state | Disposable application-schema/RLS database and concurrent transactions |
| Native lifecycle/storage | Explicit blocked requirements | Android adapter with verified PID death/relaunch, controlled storage faults |
| Web | Explicit blocked requirements | Isolated browser contexts, actual navigation/storage/console/network observations |
| Privacy | Model values excluded from exports | Exact synthetic-secret canaries across supplied logs and later authorized device/browser surfaces |
| Artifacts | Existing opaque hashing only | Packaged backup/debug inspection, installed-to-artifact identity verification |
| Functional/visual | Coverage rows only | Scripted journeys plus semantic assertions and human observations |
| Performance/media | Coverage rows only | Repeated timed samples, payload/codec fixtures, separate client/network measurements |
| iOS | Explicit blocked coverage | Supported macOS/device runner or honestly labeled guided observations |

Executing application-supplied suites, reading device state, contacting a real
environment or using accounts requires a separately specified target and permitted
actions. Do not enable production transfer, reset identity, delete real data,
publish/deploy, change billing or read real users' key stores to satisfy a test.
Independent review remains a merge/release gate; this batch is not a v1 claim.
