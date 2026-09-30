# Retained dashboard state

These are retention limits, not a guarantee about peak scanner memory or total
repository size. The dashboard's history document has a 32 MiB serialized UTF-8
ceiling, checked before replacement. Oversized existing history is left untouched
and reported as unavailable. An update crossing the ceiling is rejected, leaving
the prior committed snapshot intact, with `history_capacity_reached` and an action.

| Collection | Retention |
|---|---|
| Scan summaries (`history`) | Latest 100 |
| Suppression audit | Latest 500 |
| Remediation receipts | Latest 200, seals unchanged |
| Resolved findings | Latest 500, proofs unchanged |
| Monitor events | Latest 500 |
| First-seen identities, finding/inventory/suppression snapshots | No automatic deletion to meet capacity |
| Verified fixes, history exposures, history scan heads and acknowledgements | No automatic deletion to meet capacity |
| Web audit results | Explicit removal only; protected by document ceiling |

The five list limits predate this change. `diagnostics.retention` now publishes the
limits and cumulative pruning counts, persisted across restarts. Counts begin when
this version first observes pruning; they cannot reconstruct previously discarded
records. The dashboard displays nonzero counts. Its authenticated retained-history
download preserves the current payload and proofs, not already-pruned entries.
This export contains private repository information: store it privately. It is not
an app configuration backup and does not include the control token.

Stable repeated scans plateau; churn in identities and new audit targets can still
grow the protected collections until capacity is reached. No TTL resets first-seen
clocks, acknowledgements, or suppressions. Export and back up state before deliberate
history retirement. Starting a new history loses continuity and is never described
as remediation. Automatic archival/deletion of those collections is not implemented.

## Transactions and writers

Dashboard mutations snapshot affected state under a process-local reentrant lock.
Exceptions during mutation, capacity rejection, and stale-writer conflicts restore
that snapshot. Ordinary disk-write errors retain newer in-memory results and expose
the existing memory-only warning; they do not claim durable success. Serialization
and snapshot copying have transient memory cost beyond the 32 MiB document ceiling.

History and app config use nonblocking OS file locks plus revision checks. A stale
process must reload/restart before writing; it cannot overwrite a newer revision.
Locks are released by process exit, and a leftover `.lock` file is harmless. All
writers must cooperate: older releases, sync tools, and manual editors do not obey
these locks. Stop all dashboard processes before upgrades, rollback, or recovery.
Locks do not guarantee network-filesystem semantics or power-loss durability.

Shutdown marks the state closing before stopping monitoring. Late scan results
cannot commit and delayed startup cannot restart the monitor. This does not cancel
a blocked scanner or make its shutdown duration bounded.

## Repeatable evidence

`tests/test_state_bounds.py` covers retention and sealed receipts, rollback after
resolution mutation, capacity refusal, stale config/history writers, real subprocess
lock exclusion and abrupt exit, startup/shutdown overlap, and 441 stable scans.
`scripts/measure_state_soak.py` records timings, traced Python memory, retained bytes,
and pruning. This small synthetic offline workload is not a large-repository or
multi-platform performance claim. Existing failure/restart/removal tests remain in
`test_state_recovery.py` and `test_monitor_lifecycle.py`.
