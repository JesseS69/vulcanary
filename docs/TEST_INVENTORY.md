# Offline target inventory and retests

This is phase 2's initial offline slice. No executable, mobile archive, source archive
or backend is launched, extracted, authenticated to, or contacted. Artifact kinds
are operator declarations, not format/signature validation or proof of installation.
An artifact hash identifies local bytes, not the deployment using them.

```text
python -m vulcanary.test_inventory artifact --path app.apk --kind apk --output artifact.json
python -m vulcanary.test_inventory backend --reference-file private-build-reference.txt --output backend.json
python -m vulcanary.security_testing run --target target.json --output review-1 --history runs
python -m vulcanary.security_testing run --target fixed-target.json --output review-2 --history runs --previous RECORD_ID_FROM_FIRST_RUN
python -m vulcanary.test_inventory compare --history runs --before FIRST_ID --after SECOND_ID
```

Artifact kinds: apk, aab, ipa, source-archive. Hashing is streamed in 1 MiB chunks
with a 512 MiB ceiling and before/after identity/size/time checks. Missing, oversized,
symlinked or observably changing files become BLOCKED. Accessible bytes become
NOT_RUN, never PASS. Hashing is not a snapshot against a malicious concurrent writer;
use immutable local build artifacts. No original path is exported. Avoid network
mounts: this module does not make HTTP requests but filesystem access follows the
operator's chosen local filesystem configuration.

Backend references are opaque, bounded to 4 KiB, hashed without echoing their text,
and explicitly operator-reference-unverified. Supply environment and deployment/build
identifiers in the private reference file. It is not live deployment verification,
endpoint authorization or a credential store. Do not put passwords in it. Artifact
inventory records are not source-test targets: only phase 1's source adapter can run.
Mobile/device and backend execution require separately approved future adapters.

## Retest evidence

`--history` opts into a user-selected directory, never global app state. Each
content-addressed record preserves a sanitized run summary, the full report's digest
and optional previous-record digest. Full evidence remains in its reviewer package.
Records are create-only; identical append is idempotent. Cooperative writers use an
OS lock. A leftover `.writer.lock` is inert after process exit. No automatic pruning
or deletion occurs; operators must deliberately manage capacity.

Interrupted record writes may leave an invalid record; loading it fails closed.
Do not infer completion from file existence or overwrite it to repair history.
Preserve the original for investigation and use a fresh history directory if needed.
If reviewer export succeeds but history append fails, the command exits 2: the
package may exist but history completion is not claimed. History and export are not
a multi-file transaction. Same-user edits can replace records and recompute hashes:
this is append-only application behavior, not WORM storage, signatures or authentication.

Comparison requires matching non-null plan hash, adapter, implementation hash,
ruleset digest and check IDs, plus identical available target identities. Changed
bytes are linked and flagged but block transition claims: application lineage is
not verified by this inventory. Changed analyzer/plan also blocks transition claims.
On identical targets, FAIL→PASS is `passed_on_retest`, not an
independent security certification; FAIL→FAIL is `persistent_failure`. Unexecuted
checks never establish resolution. Missing target identity makes comparison
incompatible. Records do not touch the scanner resolution ledger or SLA clocks.

History parsing is bounded and validates identity/state fields, but it does not
authenticate the producer. Run IDs link observations, not people. This initial
inventory does not yet join a mobile artifact to a live backend deployment or assert
that any registered artifact was covered by the source-test adapter.
