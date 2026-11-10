# Security policy

## Supported versions

Security fixes are provided for the latest tagged release. Older releases should be upgraded before reporting behavior that is already corrected in the current version.

## Reporting a vulnerability

Please do not disclose exploitable vulnerabilities in a public issue. Report them privately through GitHub's private vulnerability reporting feature. Include the affected version, reproduction steps, impact, and any suggested remediation.

Do not include live credentials, proprietary source code, or unredacted scan reports. Use synthetic examples whenever possible.

## Safety model

The separate opt-in `python -m vulcanary.local_tests` command executes a bundled
synthetic SHA-256 unittest suite using an explicitly trusted, hash-pinned local
Python. It does not execute scanned repository code or accept arbitrary scripts.
It is not an OS sandbox; only trusted installations and synthetic fixtures are in
scope. See `docs/TRUSTED_LOCAL_TESTS.md` for process cleanup, output bounds and
the remaining containment limits. Normal scans never invoke this adapter.

Normal scans treat repositories as untrusted data: Vulcanary reads files without executing repository code or requiring repository credentials, and secret matches are redacted in output.

The experimental `python -m vulcanary.security_testing` workflow runs source-analysis assertions on explicitly registered synthetic Python snapshots. It never executes snapshot code or contacts endpoints. Registration bundles contain private source; only its allowlisted reviewer exports are source-free. Temporary staging is file isolation, not an OS sandbox. Production, external-suite and device execution are not implemented by this slice; see `docs/SECURITY_TESTING_PLAN.md` for their separate future acceptance gates.

Dependency admission compares committed lockfiles without installing packages and loads its policy from the trusted base checkout. Imported SARIF, ZAP, Prowler, and other scanner reports are untrusted input and are parsed without executing embedded content. The passive web audit requires an exact operator-authorized hostname, refuses embedded credentials and cross-host redirects, and performs no crawling, fuzzing, form submission, authentication, or exploitation.

Remediation is a separate, explicit workflow. Dependency and platform evaluators use detached worktrees, disable package lifecycle scripts, and return sanitized results. Applying a fix requires a clean named Git branch, uses a dedicated `vulcanary/*` branch, rescans the result, and runs only the verification commands explicitly configured by the repository owner. Failed validation restores the original branch and tracked working tree. Vulcanary does not push or merge fixes automatically.

The dashboard binds to loopback by default, sets a restrictive Content Security Policy, accepts state-changing requests only as JSON, and rejects cross-origin or cross-site browser actions. Do not expose the dashboard port through a public proxy.
