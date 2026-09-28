# Local state failure and recovery

Vulcanary keeps configured repositories in `app.json` and scan history in
`dashboard-history.json` under the local application directory. They are distinct
sources of truth: a failed scan must not remove a configured repository.

## Partial rescans

A rescan of repositories already loaded in the dashboard attempts each repository
even if an earlier scan raises an input/access error. Successful repositories update
normally. Failed repositories retain the last successful snapshot, which may be
stale; they are not treated as newly clean or resolved. The monitor and repository
card show a warning. `/api/state` and `/api/rescan` state include
`monitor.repository_errors`, with repository path, stable code
`repository_scan_failed`, explanation, and next action. Error text from repository
configuration is not echoed into this diagnostic.

Fix repository access, configuration, or imported reports and rescan. A fully
successful rescan clears these errors. The rescan lock is released after failure,
so retry is possible. This does not change finding identities, severity, policy
gates, or resolution criteria.

## Failed saves

History and app configuration writes use temporary files next to the destination
and replace the old file only after serialization/write completes. Tests inject
failures before writing, during a partial write, and at replacement. They verify
that previous bytes survive and temporary files are cleaned up when possible.

A failed history write keeps newer results in memory, surfaces
`diagnostics.persistence_error.code: history_write_failed`, and marks history as
memory-only. Check disk space and permissions, then rescan to retry saving.
A successful write clears the warning. Configuration-save failures propagate to
the caller rather than reporting success; the prior token and watch list survive.

## Unreadable or malformed history

Unreadable bytes, invalid JSON, and invalid top-level collection shapes produce
`history_load_failed`. The dashboard starts in memory-only mode and **will not
overwrite that file during this process**, even if a later scan succeeds. The
diagnostics panel gives recovery instructions.

1. Stop the dashboard so it cannot race the recovery.
2. Make a backup of the affected history file. Do not publish it: scan history is
   private local state even though secret evidence is redacted.
3. Restore a known-good history file, or move the damaged file aside to deliberately
   start a fresh history. Starting fresh loses historical continuity; it is not a
   migration or proof that old findings were resolved.
4. Restart and check that the diagnostic warning cleared before relying on durable
   history. The configured watch list and control token remain in `app.json`.

The tool does not attempt to guess missing records or repair damaged JSON. Shape
checks cover the top-level persisted containers, not every possible nested semantic
corruption. Atomic replacement protects the previous file in the tested process/I/O
failure windows; it is not a guarantee against power loss, filesystem corruption,
concurrent independent writers, or sync tools rewriting `.git` or app state.

## Remaining readiness work

This is a partial completion of the interrupted/failed-scan readiness criterion.
Startup failures that never entered the in-memory repository list still need a
dedicated retry/restart design and fault tests. Mid-commit in-memory mutation,
concurrent writer coordination, and a monitor restart fault matrix are not claimed
as solved by these tests. All tests use temporary app/history paths; they do not
modify the user's live application configuration.
