# v0.68.0 release notes

This release introduces an opt-in, experimental local test adapter that runs a
bundled Python unittest suite against synthetic SHA-256 known-answer vectors.
It requires an explicitly authorized, absolute-path Python executable, its
SHA-256 and exact version. It does not run application-supplied suites, scanned
repository commands, devices or live endpoints, and does not download tools.
Normal scanning and monitoring remain unchanged.

PASS and FAIL require completed assertions and confirmed cleanup. Missing tools,
incorrect pins or versions, empty/skipped tests, crashes, timeouts, excessive
output and cleanup failures produce BLOCKED. Reports identify target bytes,
expectations, executable and implementation; failed case numbers allow reproduction
without exporting vector values, raw output, exceptions or private paths.
The new experimental report schema is separate from scan reports and policy gates.

On Windows, Python starts suspended and is assigned to a kill-on-close Job Object
before resuming. POSIX uses a separate process group. Cleanup runs after success
as well as failure. Forced timeout and output-limit stops carry nonzero internal
exit codes even when Windows reports zero for a terminated process.

This is a partial execution-adapter foundation, not a general sandbox. It does not
deny network or filesystem access at OS level; only the bundled worker and a trusted
interpreter installation are supported. An executable hash does not authenticate
its libraries or prove its safety. A conforming result relies on that trusted
installation. Assertions do not establish cryptographic design security or
independent certification. Export checksums remain unsigned.

See [the trusted local-test guide](TRUSTED_LOCAL_TESTS.md) for the example,
resource limits and remaining boundaries. Application-supplied tests require a
separate authorization decision. Interrupted-write, rollback and duplicate-operation
synthetic suites are future work, not features of this release.

The candidate upgrade window retains 0.60.0 as its oldest tested endpoint and
advances the previous-release fixture to the hash-pinned 0.67.0 wheel.
See [upgrade and rollback procedures](UPGRADES.md). This release does not close
any additional v1 readiness criteria. Publication remains subject to final review,
green CI and fresh published-artifact verification.
