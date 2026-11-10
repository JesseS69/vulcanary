# Trusted local test execution: initial adapter

This opt-in experimental command runs a real Python `unittest` suite in a child
process. Its only supported suite checks SHA-256 known-answer vectors using that
interpreter's `hashlib`. It does not yet run application suites, repository scripts,
mobile artifacts, devices, backend endpoints, recovery flows or fuzzers. Ordinary
scans and dashboard monitoring never invoke it. It is a partial phase 3 foundation,
not completion of the broader execution-adapter acceptance gate.

Development and test authorization covers explicitly trusted local executables and
disposable synthetic fixtures only. Do not supply production data or credentials.
There is no download, package installation or discovery of tools on PATH.

## Run the bundled example

Select an absolute path to a trusted Python 3.11+ installation. Record its actual
SHA-256 and exact three-part Python version using trusted local tooling. Review the
executable and installation before authorizing it: matching a hash identifies bytes,
not their safety. A venv launcher hash does not identify its underlying interpreter,
standard library, DLLs or installation configuration; those must also be trusted.

```text
python -m vulcanary.local_tests --spec examples/security-testing/sha256-vectors.json --python ABSOLUTE_PYTHON_PATH --python-sha256 VERIFIED_SHA256 --python-version VERIFIED_X.Y.Z --authorize-trusted-local-tests --output NEW_REVIEWER_DIRECTORY
```

The example should run two assertions and PASS. Changing an expected digest to 64
zeros should FAIL. Registration, static inventory, no tests, skipped tests, crashes,
incorrect tool pins/versions, timeouts and malformed results cannot become PASS.
Missing authorization or a missing tool yields BLOCKED. Exit codes are 0 PASS,
1 FAIL and 2 BLOCKED/export failure. Expected count and observed completed/failing
counts are separate; incomplete execution has null observations, never a false zero.
Failures include one-based case numbers so a reviewer can locate the failing
expectation in the retained private fixture without exporting its values.

Inputs contain exactly `cases`, with 1–64 objects containing only `input_hex` and
`expected_sha256`. Each synthetic input is at most 4 KiB; the whole JSON document is
bounded to 256 KiB. No code, commands, endpoints, output paths or environment settings
are accepted in it. Only the bundled worker can be launched, with fixed `-I -S`
arguments. The private fixture may contain supplied values; reviewer files never do.

## Lifecycle and containment limits

Each run creates a fresh temporary directory. HOME and temporary-directory settings
point there. The child receives no inherited credentials, PATH, PYTHONPATH or user
configuration environment; Windows additionally receives SystemRoot. This is
credential minimization, not proof that a trusted executable cannot read host files.

The worker waits for a controller signal before running assertions. On Windows the
controller starts Python suspended, assigns it to a kill-on-close Job Object, and
only then resumes its initial thread (up to eight processes,
256 MiB per process). This permits venv launchers while bounding the process tree.
On POSIX it starts a new process session and kills the process group on every exit,
including success. No assertion runs if Windows job setup fails. Timeouts are
0.05–30 seconds (default 10); combined stdout/stderr is held only in memory, capped
at 16 KiB, and discarded after strict result parsing. Overflow blocks the run.
Cleanup failure also blocks completion.

**This is not an OS security sandbox.** Network and filesystem access are not denied
at OS level; the fixed trusted worker simply contains no network or application
operations. POSIX has no per-process memory cap here; a hostile process could leave
its process group. General CPU/disk isolation, hostile executables, externally
supplied test code, and cross-platform sandbox escape resistance remain deferred.
Do not use this helper as a general runner for untrusted code.

## Evidence and reproduction

`report.json` identifies the input bytes, expectation plan, pinned executable,
worker and controller implementation, version, bounds, times, cleanup and result.
It is separately versioned as `vulcanary.local-test-run.v1`; it does not enter the
source-run history ledger or ordinary policy gates. The report's observed version
comes from the trusted worker, not an independent attestation. Reproduction requires
retaining the private synthetic spec and trusted interpreter installation.

`reviewer.md` is a concise summary. `checksums.json` covers those two files; it is
unsigned, not authentication or certification. No raw process output, test input,
exception text, private path or credential is exported. Output directories must be
new. An interrupted export may leave a partial directory; missing checksums mean
incomplete export. Use a new destination after inspecting it. Failed staging cleanup
may leave a `vulcanary-local-test-` directory containing the synthetic fixture;
inspect that specific run's temporary files, never erase application data.

Tests exercise real passing/failing assertions, crash/result refusal, timeout,
output flood, child cleanup after success and timeout, minimized environment,
missing/mismatched tools, zero/skipped tests and export non-persistence. These are
implementation checks, not proof that a cryptographic design is secure.
