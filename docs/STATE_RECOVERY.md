# Local state failure and recovery

Vulcanary keeps configured repositories in `app.json` and scan history in
`dashboard-history.json` under the local application directory. They are distinct
sources of truth: a failed scan must not remove a configured repository.

## Partial rescans

A rescan of loaded repositories and pending startup targets attempts each repository
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

Startup targets are registered before the first scan. A failed first scan stays in
`monitor.pending_repositories` and is retried by each monitoring cycle or manual
rescan; it does not require a prior successful snapshot. Success removes its pending
entry and startup error. When monitoring is paused, use manual rescan or resume it.
The pending list is session state; service restart reconstructs targets from the
configured watch list. Removing a target removes only that configured path, retaining
other targets even when unavailable or absent from a one-off dashboard session.

Stopping the monitor signals its thread and waits up to two seconds. It does not
cancel an active scanner. Starting it while that thread is still stopping raises an
explicit retry error instead of silently returning or launching a duplicate. Once
the active cycle finishes, starting again creates a fresh thread. This is not a
guarantee of bounded shutdown for a hung scanner.

## Failed saves

A sibling `.lock` file (for example `dashboard-history.lock` or `h.lock` for
`h.json`) may remain after normal shutdown or a crash. Its existence does not mean
the state is locked: the operating system releases the active lock when the process
exits. Leave the file in place; deleting it while another process is running can
undermine coordination. A stale-writer warning requires reloading saved state, not
deleting the lock file.

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
uncooperative independent writers, or sync tools rewriting `.git` or app state.

## Remaining readiness work

Tests now cover real startup failure and retry, monitor stop during an active cycle
and subsequent restart, and abrupt subprocess exit immediately before history/config
replacement. The latter preserves watch-list/token bytes, first-seen history and a
sealed receipt across restart, despite leftover temporary files (which are ignored).
It is a test-owned subprocess, never execution of scanned repository code.

`tests/test_state_bounds.py` adds rollback after in-memory resolution mutation,
cooperating-process writer locks and stale-revision checks, process-death lock release,
capacity refusal, and shutdown overlapping a blocked startup scan. See
[retention and concurrency](STATE_RETENTION.md) for exact semantics. These close the
named interrupted/partial-scan acceptance cases; arbitrary termination points,
uncooperative/older writers, hung-scanner cancellation, network-filesystem locking,
and power-loss durability are not claimed as solved.
All tests use temporary app/history paths; they do not modify the user's live
application configuration.
