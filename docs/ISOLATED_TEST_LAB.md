# Isolated testing infrastructure

This opt-in reference lab reuses the bundled loopback transport and SQLite
authorization adapters and adds disposable storage fault checks. It accepts no
application URL, credentials, private keys, device serial or target command.
Normal scans and dashboard monitoring never invoke it.

```text
python -m vulcanary.isolated_lab --authorize-owned-synthetic-lab --manifest-sha256 YOUR_64_CHARACTER_MANIFEST_DIGEST --output NEW_DIRECTORY
```

The digest is an operator-declared reference. Each adapter exports its own report
and checksums; the top-level package preserves partial failures and hashes its
child reports. Infrastructure PASS always accompanies **candidate_state: NOT_RUN**.
Exit 0 means only infrastructure PASS; FAIL is 1 and incomplete execution is 2.
Do not use this command as a candidate release gate. Checksums are unsigned.

## Storage acceptance checks

| Fault boundary | Required result | Deliberate broken control |
|---|---|---|
| Before first write | Refusal; old state retained; later retry succeeds | Report false success |
| After first of two writes | Transaction rolls back both material and receipt | Commit partial transaction |
| Read-back mismatch | Refusal and rollback, then clean retry | Report false success |
| Before receipt write | Material rolls back with receipt | Commit material without receipt |
| Commit followed by lost acknowledgement | Fresh connection sees committed material/receipt; retry does not install twice | Duplicate installation |
| Captured session epoch becomes stale | No writes or success, including retry | Ignore session epoch |
| SQLite capacity | Actual SQLITE_FULL; prior state retained and retry succeeds | Report false success |

The capacity probe requests 128 KiB inside a database limited to 16 pages. It does
not fill the host disk. Every case uses a fresh owned temporary directory, two fixed
synthetic byte records and bounded SQLite lock waits. Fresh connections inspect
the committed state. Failure to activate a fault, setup failure, unexpected database
error or cleanup failure yields BLOCKED. No raw rows, bytes, paths or exception text
enter reports. All seven cases have tested mutation controls, including optimized
Python execution. No cryptographic design or application key-store claim is made.

Run storage checks alone:

```text
python -m vulcanary.storage_tests --authorize-disposable-storage --manifest-sha256 YOUR_64_CHARACTER_MANIFEST_DIGEST --output NEW_DIRECTORY
```

## Remaining application integration, in order

1. **Isolated application deployment:** provide an application-owned local/staging
   configuration with outbound destinations fixed, disposable accounts/tenant IDs,
   feature eligibility and build identity. Verify production endpoints are refused
   and cleanup can affect only run-owned records. This lab cannot manufacture that
   deployment from a production session.
2. **Candidate storage port:** use an explicitly trusted test build/adapter to expose
   installation, receipt and session-generation boundaries. Re-run this fault matrix
   against that implementation with source/artifact identity recorded. A temporary
   directory alone is not an OS sandbox for target code.
3. **Candidate transfer journey:** connect the application adapter to the existing
   owned-loopback transport faults; preserve server outcome separately from client
   acknowledgement. Include refusal, response loss, duplicate retry and stale-account
   completion. A bundled relay PASS cannot satisfy this step.
4. **Native lifecycle and privacy:** Android test build on a disposable emulator;
   iOS requires an authorized macOS/Xcode runner. Prove actual process termination,
   restart and storage rollback with synthetic key history, then capture only scoped
   canary evidence. Neither platform is provisioned automatically here.
5. **Web and visual/performance:** dedicated test browser profile, pinned deployment,
   allowlisted network capture and synthetic media. Measure content-ready latency
   and peak memory with fixed workloads; independent usability needs a human.

The existing installed-device observations remain separate: they do not validate
an isolated transfer deployment, and these reference tests do not close their
blocked requirements. Application bug fixes stay in the application's backlog.
