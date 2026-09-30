# Repeatable release gate

Record the commit, candidate version, command/workflow URL, date, result and reviewer
for each item. The reviewer must not be the author. A green checklist is evidence
for this candidate, not permanent approval for future commits. Do not mark pending
CI, unrun installed-wheel checks or unreviewed work complete.

- [ ] Clean candidate checkout; exact base and diff reviewed; no unrelated work.
- [ ] Source and package metadata agree; proposed tag is unused.
- [ ] Full supported-platform CI, parser robustness, security non-persistence tests
      and official-schema checks pass from the candidate wheel.
- [ ] Offline self-scan passes. New detector behavior has positive and negative
      external corpus evidence; report exposure/gap/truncation identity changes,
      workload, runtime and limits, not just counts. Tooling-only batches say so.
- [ ] State failure, retention, capacity, simultaneous/stale writer and shutdown
      tests pass. Synthetic soak results include retained bytes, memory and latency.
- [ ] Declared oldest and previous published wheels pass direct upgrade/rollback
      rehearsals and the sequential path. Use isolated homes, never live user state.
- [ ] Findings, first-seen, suppressions, acknowledgements and proofs retain identity;
      any intentional breaking report change has explicit compatibility notes.
- [ ] Documentation warnings have a next action; limitations and v1 readiness rows
      match measured scope. Public screenshots/data are synthetic and privacy-checked.
- [ ] Independent review approves the exact final diff; new commits rerun affected
      checks. Merge only after required CI is green.
- [ ] After merge, verify clean main equals remote and tag target; publish immutable
      artifacts with a new version. Never rewrite an already published release.
- [ ] Download fresh artifacts; verify all four manifest-covered assets (wheel,
      sdist, installer, uninstaller). The fifth asset is the manifest, not self-hashed.
- [ ] Fresh-environment installed-wheel smoke and installer checksum-gate check pass;
      verify packaged assets, version, representative behavior and offline self-scan.
- [ ] Release notes name behavior changes, scope, benchmark tradeoffs, remaining
      limits and rollback procedure. Obtain independent artifact verification.
- [ ] Remove only the merged feature branch; preserve unrelated work. Update the
      readiness ledger from evidence and record remaining blockers, not a v1 promise.

See [upgrade policy](UPGRADES.md), [state retention](STATE_RETENTION.md),
[state recovery](STATE_RECOVERY.md), [report contracts](REPORT_CONTRACTS.md) and
[v1 gate](V1_READINESS.md). Remediation PRs in scanned repositories, new trust
boundaries and other standing stop conditions still require explicit authorization.
