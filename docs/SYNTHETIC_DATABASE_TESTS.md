# Disposable database permission and concurrency contracts

This adapter tests a bundled SQLite schema with disposable synthetic accounts.
It does not accept a database URL, credentials, migrations, application code or
SQL from the candidate. It never contacts Zirze or a deployed database.

```text
python -m vulcanary.database_tests --authorize-disposable-database --manifest-sha256 YOUR_64_CHARACTER_MANIFEST_DIGEST --output new-database-review
```

Eight checks run against fresh, temporary databases:

- another account cannot read or claim the transfer;
- an expired or logged-out session cannot claim it;
- an unapproved, expired or revoked transfer cannot be claimed;
- two receivers contend for the same transfer, and exactly one succeeds.

Each denial compares the entire transfer row before and after the attempted action.
The race starts two threads together, each with its own SQLite connection, and
executes an atomic conditional UPDATE. A successful transaction is committed
before it is counted as accepted. The stored claimant must match the sole winner.
Five independent races run; winner identity is intentionally not fixed. The test
suite removes the atomic claim predicate and verifies both contenders succeed,
causing FAIL. Other negative controls bypass tenant, session, approval, expiry
and revocation checks, and each corresponding assertion must fail. The test suite
also requires an explicit negative control for every check in the case catalog.

This is **not RLS validation**: SQLite authorization here comes from the bundled
query predicates, not database-user privileges. Deployed PostgreSQL/Supabase
policies, service-role access, application migrations and authentication providers
remain untested. Session expiry uses a fixed synthetic clock. A manifest digest is
an operator-declared reference, not proof this database belongs to that candidate.
These results cannot close application authorization or concurrency requirements.

Database locking waits at most one second. The race barrier waits at most two
seconds, and joining both workers has a shared five-second deadline. Missing
worker results or database errors remain BLOCKED. All connections close before
the temporary directory is removed. Cleanup failure cannot produce PASS. Only
run-created directories are deleted; there is no cleanup option for supplied paths.

Reports retain expected and observed counts for every repetition, Python/SQLite
versions, implementation digest, explicit limits and cleanup status. Exports omit
database paths, synthetic account IDs, raw rows, SQL and exception details. JSON,
Markdown and unsigned checksums are written to a new directory. No scan gates,
SLA records, dashboard state or normal scan behavior changes.

Exit 0 means all bundled assertions passed; 1 means an assertion failed; 2 means
execution was incomplete or blocked. BLOCKED takes aggregate precedence while
individual failures remain visible. Five races demonstrate sampled schedules,
not correctness under every possible interleaving or independent certification.
