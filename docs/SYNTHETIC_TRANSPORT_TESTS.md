# Bundled synthetic HTTP fault tests

This adapter tests the bundled relay's behavior through real loopback HTTP sockets
and disposable SQLite transactions. It never takes a target URL, invokes target
code, or contacts an application backend. A PASS is harness evidence, not evidence
that Zirze or another application implements the same behavior.

```text
python -m vulcanary.transport_tests --authorize-owned-loopback --manifest-sha256 YOUR_64_CHARACTER_MANIFEST_DIGEST --output new-transport-review
```

The manifest digest is an operator-declared reference only. It does not authenticate
or bind application behavior. These results do not automatically satisfy a
candidate's real-transport, database, device, or cryptographic requirements.

Five scenarios run, each with its own temporary database and owned server:

| Scenario | First server outcome | First client outcome | Retry expectation |
|---|---|---|---|
| before-upload-commit | no write | uncertain | one committed upload |
| lost-upload-response | upload committed | uncertain | still one upload |
| lost-completion-response | completion committed | uncertain | still one completion |
| stalled-before-upload-commit | no write | timed_out | one committed upload |
| stalled-after-upload-commit | upload committed | timed_out | still one upload |

The server closes its response socket after the transaction commits in the two
response-loss scenarios. The client actually receives no HTTP response. Reports
preserve the first uncertain attempt even after the retry succeeds. The first
scenario reaches the server and drops before committing; it does not prove offline
device behavior or a connection failure before arrival at a server.

The two stalls hold the first response behind an event. The client waits for the
handler to reach that fault point, then attempts to read with a 250 ms socket
timeout. This is an actual socket timeout, not a mocked outcome or a sleep used as
an assertion. The controller inspects the separate SQLite ledger before releasing
the handler and retrying on a new connection. A timeout alone never implies that
the server rolled back. The before-commit stall discards the original attempt;
it does not model a delayed transaction that commits after the client times out.

The handler's wait is capped at three seconds and cleanup releases it even when
the client fails. Fault activation has a one-second wait limit. Ordinary requests
retain their one-second timeout. No host networking configuration is changed;
these timings are harness bounds, not measurements of application performance.

The relay accepts only two fixed POST paths, empty bodies and a private per-run
nonce. It binds 127.0.0.1 on an ephemeral port. The client uses that owned port,
without DNS, proxies, redirects or operator-supplied endpoints. Each scenario has
at most three requests; accepted sockets and ordinary client requests have a one-second
timeout. The server thread is stopped and sockets/database handles closed before
temporary data cleanup. Cleanup failure remains BLOCKED. These controls are not
an operating-system network sandbox for arbitrary code; no arbitrary code is run.

The five fixed scenarios produce PASS only from observed assertions. The test
suite deliberately enables duplicate writes on committed-response retry paths,
commits when no write is expected, and misreports timeouts as success. Each relevant
control must fail. Expected counts come from the scenario contract, not relay
configuration. Assertions still execute with Python optimization enabled.
Missing loopback access, database errors and incomplete cleanup cannot yield PASS.

Exports contain JSON, a short reviewer document and unsigned checksums. They omit
run tokens, source paths, request headers, database contents and raw exceptions.
State and counts must both be read: BLOCKED takes precedence over FAIL, while a
failure in another scenario remains in its row. Exit 0 means all five harness
scenarios passed, 1 means an assertion failed, and 2 means blocked/error.

This is not deployed database/RLS or concurrency testing. SQLite stores operation
counters, not real keys or transferred media. No TLS, mobile lifecycle, verified
native process death, key installation, account switching, or storage rollback in
an application is exercised. Those require their own authorized target adapters.

## Report compatibility

This increment emits `vulcanary.synthetic-transport-run.v2`, with two additional
scenario IDs, `timed_out` client outcomes and explicit stall limits. It does not
silently extend the v1 enum contract. Consumers must explicitly accept v2; no
existing candidate evidence importer or policy gate is connected to either form.
