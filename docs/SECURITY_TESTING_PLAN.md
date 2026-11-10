# Security-testing platform: phased implementation

## Product boundary

Help small teams repeat implementation checks, investigate failures and prepare
reviewable evidence. This is not independent certification, a cryptographic-design
review, or a claim of complete penetration testing. Ordinary scans retain their
non-executing behavior. The test workflow is opt-in and separate from dashboard
monitoring, findings gates, SLA clocks and remediation receipts.

Platform work belongs here; an individual app's failing checks and remediation
backlog belong with that app. Reusable adapters define capabilities, not fixes for
one named application. Development approval does not authorize a live engagement.

## Inspection: reuse and missing pieces

| Existing implementation | Reuse | Boundary / missing feature |
|---|---|---|
| `scanners.py`, `dependencies.py`, `config.py` | Real source and dependency analysis, bounds, ruleset manifest | Not an application test runner; ordinary scans must not run project commands |
| `adapters.py` | Normalize externally produced security reports | Import is not execution; imported PASS cannot prove a test ran |
| `models.py`, `reporters.py`, `provenance.py` | Versioning, hashes, evidence export patterns | Findings/severity are not check outcomes; unsigned hashes are not certification |
| `state_store.py`, history/receipt tests | Durable-state safeguards and continuity regression tests | New run storage and retest links need their own schema, no borrowed SLA semantics |
| `fixes.py`, `evaluator.py` | Lessons from shell-free execution, timeouts, explicit trust | Verification commands execute trusted code; these helpers are not sandboxes and will not be reused as unrestricted runners |
| `history_secrets.py`, secret non-persistence tests | Explicit tool trust, redaction, lifecycle separation | No credentials or raw tool output should silently reach reviewer packages |
| `webaudit.py` | Explicit host scope and passive checks | Not a browser/API authorization runner; cannot provide containment for new active tests |
| Corpus/contract/upgrade tests | Identity comparisons, reproducibility and validation infrastructure | Need workflow-specific negative controls, cleanup and scope-escape tests |

## Phases and acceptance gates

Each phase is a separately reviewable increment. Do not mark a phase complete just
because its report fields exist. The first implementation below covers phase 1
only; no external executable, live service, device, account or secret is configured.

| Phase | Deliverable and missing capability | Dependencies | Acceptance evidence |
|---|---|---|---|
| 1 — smallest useful workflow | Register a bounded isolated synthetic source snapshot; execute the existing source scanner as an assertion adapter; source-free reviewer package | Existing scanner, fixed config, target/plan digests, five-state result model | Real positive and negative assertions; invalid/tampered/unreadable input BLOCKED; manual NOT_RUN; deferred DEFERRED; source never executes; no network/process launch; deterministic retest observations; no raw source/secret in package |
| 2 — target inventory and run history | Android APK/AAB, iOS IPA/source/build references, backend environment identities; immutable artifact/source digests; evidence-to-build mapping; append-only retest links | Phase 1 identity contract; artifact size/type validation; local trusted registry | Changed bytes create a new identity; inaccessible artifact BLOCKED; backend deployment ID/build digest verified where available, otherwise identity uncertainty explicit; local artifact identity never implies it was tested on a device |
| 3 — execution adapters | Explicitly configured existing unit/integration suites and established analysis tools; structured results and provenance | Phase 2; trusted executable/version pins; disposable runner; credential minimization; bounded logs, disk, CPU, timeout and process-tree cancellation | Real suite pass/fail/zero-tests/crash/timeout cases; missing tool BLOCKED, never PASS; malicious target cannot change runner scope; arbitrary stdout excluded; all children stopped; shell-free arguments alone never described as isolation |
| 4 — fixtures and backend authorization | Versioned endpoint/action scope, permission matrices, disposable users/tenants, bounded records/pagination/concurrency fixtures | Phase 3 containment; exact authorized target; synthetic account provisioning; application-owned setup/cleanup contract | Negative cross-account reads/writes, switching accounts with pending responses, expired sessions/logout; confirm old-account state cannot update new session; setup failure BLOCKED; cleanup is idempotent, confined to run-owned IDs, and auditable |
| 5 — lifecycle and network faults | Offline, bounded latency, stalls, dropped responses, reconnection; restart, background/foreground and interrupted operation | Phase 4 repeatable fixtures; controlled test proxy/network harness; backend event ledger; Android/iOS test runners | Replay each deterministic schedule; assert retry ceilings, idempotency, duplicate writes, stale-response rejection and recovery; distinguish client timeout from confirmed server outcome; no host-wide networking changes |
| 6 — crypto integration | Adapter-driven known-answer vectors, negative/malformed inputs and bounded fuzzing; key-transfer/recovery state transitions | Phase 3 runner; trusted vector sets and external implementations; synthetic keys; rollback-safe fixture storage | Tampering, wrong key, substituted identity, replay/expiry and partial-write cases; failed transition leaves expected prior state; never erase real keys to create a condition; state clearly that these checks do not validate cryptographic design |
| 7 — mobile device and privacy | Android emulator/physical-device and iOS simulator/physical-device workflows; app-switcher previews, protected screens, permission/keyboard flows, accessibility sizing; marker search in supported storage/log outputs | Phase 3; separately installed platform tools; macOS/Xcode/signing and device permissions for relevant iOS work; explicit test-device selection | Device/build/OS version recorded; missing hardware BLOCKED; human observation NOT_RUN until attested; approved synthetic markers detected in logs/storage; screenshots reviewed/redacted before export; emulator results not represented as physical-device evidence |
| 8 — reviewer delivery and validated production option | Reproduction recipes, minimal evidence, unresolved questions, fix/retest history and concise exports; carefully scoped production support only if approved | Prior isolation/cleanup evidence; schema contracts; operator identity and engagement scope; secret-storage design and separate live-target authorization | Old failure remains immutable; retest links target/build and plan changes; PASS not inferred from absence; production default denied, never enabled by scanned config; permitted actions/time window and scope enforced by runner; network observation proves lab containment; external reviewer makes their own conclusions |

Prioritize phases 2–5 according to an actual team's stack after phase 1 review.
External adapters require an explicit installation/trust decision, not an automatic
download. Production and credentialed backend testing are deliberately not present
in the first slice. Approval must name the environment and permitted operations;
an operator declaration is not independent proof of authority.

Phase 1 approval does not authorize the execution boundaries in phases 3 and beyond.
Before implementing each such phase, explicitly resolve the applicable standing
merge gate 7 decisions (external executables, credentials, active testing or work
outside Vulcanary). Approval of a platform capability still does not authorize
running it against any particular live environment or device.

## Cross-cutting invariants

- PASS: a named assertion actually executed and matched its expectation. A check
  that expects one finding can PASS while demonstrating deliberately unsafe code.
- FAIL: a completed assertion disagreed with expectation. BLOCKED: execution or
  required evidence could not complete. NOT_RUN: no completed execution/observation.
  DEFERRED: consciously excluded from this run, never a synonym for PASS.
- Carry expected and observed results, exact target and plan IDs, adapter/tool and
  ruleset versions, evidence method, timestamps, limitations and cleanup status.
- Reproduction must not require putting raw credentials in a report. Use private
  fixture references, generated file IDs and sanitized observations. Hashes establish
  identity/integrity, not who ran a test or whether the runner was trustworthy.
- Never merge partial test outcomes into ordinary scanner findings or policy gates
  implicitly. No normal scan starts a device, process, proxy or active network test.
- Measure failed cleanup, attempted scope escapes, unintended mutations, interrupted
  runs, false passes and unexecuted tests as carefully as successful detections.
- Sandbox claims require a concrete enforcement layer and adversarial lab evidence.
  Temporary directories and copied environment variables do not constitute one.

## First slice: how to run

The separately authorized [trusted local-test adapter](TRUSTED_LOCAL_TESTS.md)
starts phase 3 with a bundled SHA-256 unittest suite on disposable synthetic vectors.
It launches an explicitly trusted, hash-pinned Python, not repository code. This is
a partial foundation: arbitrary suites, live endpoints, devices and general OS
sandboxing remain outside its scope. Phases 1–2 retain their non-executing behavior.

The subsequent [offline inventory and retest slice](TEST_INVENTORY.md) adds bounded
artifact hashing, explicitly unverified backend references and append-only source-run
summaries. It does not implement live deployment identity verification or execute
mobile/backend artifacts; phase 2 is not claimed complete in its general form.

Use the repository fixture, which contains a deliberately unsafe expression and a
clean control, not any private application's code:

```text
python -m vulcanary.security_testing register --spec examples/security-testing/source-fixture.json --target target.json --authorize-isolated-synthetic-source
python -m vulcanary.security_testing run --target target.json --output reviewer-run-1
```

Registration reports NOT_RUN. Execution should report FAIL: the zero-eval assertion
fails, the zero-pickle assertion passes, device privacy is NOT_RUN and backend
authorization is DEFERRED. This is an actual invocation of Vulcanary's scanner,
not a mock adapter or evidence imported from a previous scan. The fixture contains
a module-level exception that must never execute.

The private `target.json` stores the source snapshot. **Do not publish it as sanitized
evidence or place live secrets in it.** A generated reviewer directory contains only
`report.json`, `reviewer.md`, and `checksums.json`. Output directories/files must be
new; existing files are never replaced. Package checksums cover the two report
files, not themselves. The manifest is unsigned and unauthenticated: it detects
accidental corruption against an unchanged manifest, not replacement of both the
evidence and manifest, and does not establish authorship or authenticity.
An interrupted export may leave a partial directory; absence
of the final checksum file means export is incomplete. Use another output directory
after reviewing any partial output. Cleanup removes only the temporary directory
created for this execution, never the input snapshot or an application directory.
If cleanup is not confirmed, inspect only the operating-system temporary directory
whose prefix contains `vulcanary-security-` and that report's run UUID; retained
staging can contain source. Do not broadly clear temporary or application storage.

Inputs: exactly `files` (1–16 Python source strings, at most 64 KiB each) and `checks`
(1–64 declarations); documents are bounded to 256 KiB. Ordinal files are reconstructed
as `source-001.py`, etc. Arbitrary paths, commands, endpoints, source configuration,
inline suppression directives and malformed Python are not accepted. Scope is fixed
to offline source checks, no accounts/endpoints and no production authorization.
All snapshots use the built-in default scanner configuration. Missing/skipped files
block every automated assertion rather than becoming a false zero-count pass.

Automated declarations use `method: automated`, a supported Python/secret `rule` and integer
`expected_count`. Counts cover the whole snapshot. Manual/deferred declarations use
`method: manual` or `deferred` with `kind` from `device-privacy`, `accessibility`,
`backend-authorization`, `crypto-integration`. They do not execute and cannot be
marked passing in this implementation. All scanner observations are exported as
rule/file/line triples, even if a rule has no explicit assertion; a passing assertion
does not mean those other observations were accepted or tested.

Each run is new; repeating identical snapshot/plan retains their digests but not the
run UUID. The implementation digest binds the adapter, scanner, configuration and
finding-model module bytes, distinguishing development builds sharing a version.
It is a code identity, not a signed attestation or complete environment fingerprint.
`attempted` indicates an adapter invocation; `executed` means completed
analysis and cleanup sufficient to evaluate the assertion. BLOCKED observations
are null, not zero. Aggregate precedence is BLOCKED, FAIL, NOT_RUN, DEFERRED, PASS.
Exit 2 means blocked/error, exit 1 means assertion failure, exit 0 means neither;
NOT_RUN/DEFERRED still require inspecting counts. These exits are test assertions,
not changes to scan-policy exits. This experimental module entry point is distinct
from the stable `vulcanary` CLI. No manual attestation editor, device integration,
live backend test, historical run database or automated fix is claimed yet.
