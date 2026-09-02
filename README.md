<p align="center"><img src="src/vulcanary/dashboard_assets/vulcanary-logo.png" alt="Vulcanary canary and forge hammer logo" width="128"></p>

# Vulcanary

Vulcanary is a local-first code defense system that finds vulnerabilities, tests remediation paths, and turns verified repairs into reviewable Git commits. Its forge-inspired dashboard watches multiple repositories, normalizes findings from built-in and external engines, and keeps source code under the operator's control.

The complete local scanner, dashboard, continuous monitoring, GitHub workflow, dependency admission gate, passive web audit, cloud/DAST report adapters, remediation engine, reports, and benchmark are available in the free community edition. It requires no Vulcanary account, telemetry, hosted control plane, or paid service.

The canary detects trouble; the forge proves the repair. Vulcanary evaluates dependency and platform upgrades in isolated Git worktrees, runs the repository's own verification commands, rescans the result, and unlocks a fix only when the tested findings disappear without breaking configured checks. It can also enforce the same policy in GitHub Actions and produce normalized JSON, SARIF, and CycloneDX reports.

## Quick start

Python 3.11 or newer is required.

Install a tagged Windows release by downloading `install-windows.ps1` from that release, reviewing it, and running:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-windows.ps1
```

The installer downloads the release wheel and checksum manifest, refuses a checksum mismatch, installs for the current user, and opens guided setup. To install from a local checkout instead:

```powershell
cd vulcanary
py -3 -m pip install --user .
vulcanary setup
```

Setup accepts one or more repository paths and stores them only in `~/.vulcanary/app.json`. Then manage the loopback service without remembering dashboard arguments:

```powershell
vulcanary start
vulcanary status
vulcanary stop
```

`start` binds the loopback dashboard first, then loads initial repository scans in a background worker so a large dependency graph cannot produce a false startup failure. The dashboard's **Diagnostics** panel reports startup progress, scanner warnings, runtime versions, and local-history availability. The control token is generated locally, stored in the user-local application configuration with restrictive permissions where the operating system supports them, and passed to the child process through its environment rather than command-line arguments.

Every state-changing dashboard endpoint requires that token in an `X-Vulcanary-Control` header, including scanning, remediation, monitoring changes, and shutdown. A loopback bind is a reachability limit, not an authorization boundary: on a shared or multi-user machine any local process can connect to `127.0.0.1`, and remediation can execute repository-defined verification commands. `start` therefore opens the dashboard at a URL carrying the token once; the page keeps it for that tab only and immediately removes it from the address bar so it is not retained in browser history. With `--no-open`, the authorized URL is printed for you to paste. Opening the dashboard without a token still shows findings but leaves every action locked.

Read-only endpoints remain unauthenticated so `vulcanary status` can report service health without holding the token. Findings are therefore readable by other local processes; treat the machine running Vulcanary as trusted.

OSV advisory normalization ignores withdrawn records, derives qualitative severity from CVSS v3 and v4 Base vectors when OSV does not publish a textual rating, and records the score and vector with each finding. Fixed-version selection prefers the nearest compatible stable release so a prerelease is never recommended when a stable patched version is available.

Back up or restore local service configuration without copying the control token, scan history, findings, receipts, command output, or source:

```powershell
vulcanary config-export .\vulcanary-config.json
vulcanary config-import .\vulcanary-config.json
```

Imports validate the schema, loopback binding, port, interval, and every repository path before atomically replacing the current configuration. The existing local control token is retained.

Windows releases also include `uninstall-windows.ps1`. It stops the local service and removes the Python package while preserving `~/.vulcanary` by default. Run it with `-PurgeLocalData` only when you intentionally want to delete configuration, scan history, receipts, and audit records.

Run `vulcanary update-check` when you want to query the official GitHub release endpoint. It reports availability and never downloads or installs an update automatically.

For a one-time command-line scan, run `vulcanary path\to\repository --json findings.json --sarif findings.sarif`.

The process exits with code `1` if a finding meets the configured `fail_on` severity. Use `--no-fail` for audit-only runs.

To scan several independent local repositories without adding Vulcanary to them:

```powershell
.\scripts\scan-many.ps1 ..\CabinScout ..\worktime-audit C:\path\to\zirze-native
```

## Local dashboard

Launch the dashboard and optionally scan one or more repositories immediately:

```powershell
vulcanary dashboard `
  --repository ..\CabinScout `
  --repository ..\worktime-audit `
  --repository C:\path\to\zirze-native
```

The dashboard runs only on `127.0.0.1` by default. It provides repository summaries, live threat temperature, searchable findings, dependency inventory changes, a local scan ledger with per-repository finding deltas, governed exceptions, and guarded remediation. Its **Web & cloud security** panel can run the native one-request passive web audit only after the operator types the exact authorized hostname, and explains how to import a locally generated, read-only Prowler JSON-OCSF report without giving Vulcanary cloud credentials. Normalized web findings survive local dashboard restarts; response bodies are never stored. Scanned source and findings remain on the local machine.

On first run, **Find nearby repositories** looks for Git directory markers and offers them as setup candidates. Discovery runs only after that click, reads directory names only, stops at a bounded depth, ignores common generated/private application folders, and never scans a candidate until the operator selects it. Web-audit history includes **Rerun** and **Remove** controls; rerun deliberately clears the authorization field so every new network request requires the hostname to be typed again.

Continuous watch rescans every five minutes by default. The dashboard can pause or resume it, change the interval from one minute to 24 hours, or trigger an immediate cycle. Only new, reopened, and severity-increased findings create monitor alerts; the first scan is a quiet baseline. Alerts retain a source-free finding identity, repository-relative path, timestamp, and Git commit when available. The browser polls local state for status updates, while all scanning remains inside the loopback process. Start paused with `--monitor-interval 0`, or choose a 30–86400 second interval on the command line.

Repositories can be added and removed directly from **Repository watch**. The local application configuration is updated atomically, while scan history and closure evidence remain available after a repository is removed. Each card reports builtin/dependency scanner health, Git branch and commit, scan duration, inventory state, ownership, and finding counts. Browser desktop alerts are optional, require an explicit permission click, and are generated locally only for new monitor events.

### Guarded fixes

Eligible findings have checkboxes in the remediation queue. **Select all safe fixes** collects deterministic upgrades, while **Evaluate all blocked fixes** deduplicates shared parent and platform paths and tests them without touching the watched branch. Findings are labeled with an actionable state: automatic fix, evaluate, draft source fix, or no patched release.

Select verified findings and choose **Preview fixes** to review the exact candidate and affected files. Vulcanary requires a clean Git worktree, creates a dedicated `vulcanary/fixes-*` or `vulcanary/fix-expo-*` branch, applies the evaluated change with lifecycle scripts disabled, rescans the repository, and runs explicitly configured project checks. **Commit verified fixes** appears only after every selected advisory is cleared and every check passes. A failed rescan or project check restores the original branch and working tree. Vulcanary never pushes or merges a fix branch automatically.

Every passing batch receives a tamper-evident remediation receipt containing the selected finding fingerprints, changed files, rescan result, sanitized project-check results, branch, timestamp, and SHA-256 proof. The receipt is shown before commit and retained in the local remediation audit; the dashboard refuses to commit a batch without a passing receipt.

The dashboard's **Verification receipts** panel validates stored proof hashes on every load and marks altered records invalid. Successful verification, committed repairs, and safely rolled-back failures all receive receipts, so rejected changes remain auditable without being mistaken for fixes. Individual receipts can be downloaded as normalized JSON; downloads contain sanitized verification metadata but never raw command output, environment values, credentials, or source content.

The **Resolved findings ledger** turns the first scan into a local baseline and records findings that disappear on later scans. Each closure contains the stable fingerprint, minimal finding identity, first/last-seen times, resolving Git commit and branch when available, ruleset digest, resolution route, linked remediation-receipt proof when Vulcanary performed the repair, recurrence number, and its own SHA-256 proof. A returning fingerprint reopens and reseals the record rather than silently appearing as a new issue. `observed_resolved` means Vulcanary observed the finding disappear; it does not claim a particular change caused the result. Dependency closures are attributed to `dependency_update` only when the dependency inventory changed, while a valid committed dashboard receipt produces `verified_vulcanary_fix`.

Closure records can be downloaded as normalized JSON. They deliberately exclude evidence, source snippets, absolute repository paths, command output, credentials, and environment values. The ledger remains in `~/.vulcanary/dashboard-history.json`; it is not uploaded to GitHub or included in scan artifacts.

Supported source findings expose **Draft fix** instead of a disabled checkbox. Source recipes are deliberately structural and fail closed when the source shape differs from the reviewed pattern. The dashboard displays a unified diff before application, creates a `vulcanary/source-fix-*` branch, and subjects the draft to the same project-check, rescan, rollback, guarded-commit, and remediation-receipt workflow. Reviewed recipes replace a narrowly recognized static `innerHTML` construction with explicit DOM nodes and `textContent`, convert standalone Python `eval` calls over simple data values to `ast.literal_eval` with safe import placement, remove `shell=True` when a subprocess call already uses a static string-only argument list, disable persisted checkout credentials, and reduce workflow-wide `write-all` to a read-only baseline for subsequent least-privilege review. Dynamic HTML, nested calls, executable Python expressions, string commands, interpolated subprocess arguments, and workflow-specific write grants remain review-only.

## Configuration

Copy `.vulcanary.example.json` to `.vulcanary.json` in the repository being scanned:

```json
{
  "fail_on": "high",
  "exclude": ["fixtures/**"],
  "ignored_rules": ["CODE-JS-INNERHTML"],
  "ignored_fingerprints": [],
  "suppressions": [{
    "fingerprint": "0123456789abcdefabcd",
    "reason": "deferred",
    "owner": "security@example.com",
    "justification": "Waiting for a verified upstream remediation.",
    "expires": "2026-12-31"
  }],
  "max_file_bytes": 1000000,
  "verify_commands": [["npm", "test", "--", "--runInBand"], ["npm", "run", "build"]],
  "verify_timeout_seconds": 300,
  "dependency_policy": {
    "deny_packages": ["unapproved-package"],
    "deny_licenses": ["GPL-3.0"],
    "allow_install_scripts": false,
    "allow_non_registry_sources": false,
    "require_npm_integrity": true
  }
}
```

Verification commands are opt-in and executed directly without a shell after a proposed dependency fix passes its security rescan. Command output is not returned to the dashboard, preventing accidental leakage of tokens or other build-log secrets.

> **Trust boundary: `verify_commands` comes from the scanned repository.**
> Vulcanary reads `.vulcanary.json` from the repository being scanned, so `verify_commands` is controlled by whoever controls that repository's contents. Scanning is always read-only and never runs repository-defined commands. **Applying a fix does run them**, on your machine, with your user account.
>
> In practice this means:
>
> - Adding, scanning, and reviewing findings for an untrusted repository is safe.
> - Applying or committing a fix in a repository you do not trust is equivalent to running its build scripts. Read its `.vulcanary.json` first.
> - Treat a pull request that adds or edits `verify_commands` as a code-execution change and review it as one.
>
> Commands run without a shell, from an argument array, under `verify_timeout_seconds`. That prevents shell metacharacter injection; it does not make an untrusted command safe.

Repositories can declare `repository_owner`, `security_contact`, and severity-specific `remediation_sla_days` in `.vulcanary.json`. The dashboard records when each stable finding fingerprint was first seen, calculates its deadline, and labels it on track, due soon, or overdue. First-seen history remains local and survives rescans so unresolved findings cannot reset their deadline by moving lines.

Normalized JSON and SARIF reports preserve the configured owner, security contact, and SLA durations. Absolute deadlines remain dashboard-only because CI jobs do not have the durable first-seen history required to calculate them honestly.

### Risk acceptance and expiration

Structured `suppressions` are fingerprint-scoped and require a reason (`false_positive`, `mitigated`, `accepted_risk`, or `deferred`), owner, meaningful justification, and ISO expiration date. Active exceptions suppress only the matching finding. Exceptions expiring within 14 days are highlighted in the dashboard; expired exceptions stop suppressing the underlying finding and add a high-severity governance finding that fails the default CI policy. Invalid, duplicate, or incomplete entries fail configuration loading.

The dashboard displays the current register and persists exception additions, changes, and removals in the local audit file at `~/.vulcanary/dashboard-history.json`. Justifications and audit events are never uploaded by Vulcanary. Legacy `ignored_fingerprints` and blanket `ignored_rules` remain compatible but generate medium-severity unmanaged-exception findings until converted to structured fingerprint suppressions.

### Parent upgrade evaluation

Repositories with vulnerable transitive dependencies expose an **Evaluate upgrade paths** action. Vulcanary queries npm for the latest compatible release line of each traced direct parent, checks out a temporary detached Git worktree, installs the candidate with lifecycle scripts disabled, and performs a fresh OSV rescan. Configured verification commands run only after the candidate clears its targeted advisories. The watched branch is never modified, temporary worktrees are removed after every candidate, and npm/build output is excluded from the dashboard response.

Results distinguish safe candidates, partial improvements, still-vulnerable releases, dependency conflicts or platform migrations, failed project checks, and missing compatible releases. Pre-1.0 dependencies are constrained to their current minor line because minor releases may contain breaking changes.

Expo repositories also expose coordinated platform evaluation. Vulcanary first tests the latest release on the current SDK line, lets Expo align its supported React Native, Router, and module versions together, runs `expo install --check`, and then applies the same advisory and project-verification gates. Advisories cleared by a candidate that passes configured checks become selectable verified fixes. A separate action can test the next Expo SDK line as an explicit migration experiment; a migration with unresolved findings or failing checks remains a review-only draft.

After a platform evaluation, the dashboard offers JSON and SARIF migration reports. Reports include resolved and remaining advisory IDs, proposed direct-package version changes, modified repository-relative files, verification stages and exit codes, and sanitized TypeScript diagnostics containing only error code, relative path, line, and column. Raw compiler/build output, diagnostic messages, source snippets, command arguments, environment values, and absolute local paths are excluded.

An explicit migration evaluation can also enable **Create draft migration branch**. This action is limited to the exact candidate Vulcanary just evaluated, requires a clean Git working tree and a named current branch, and creates a timestamped `vulcanary/migrate-expo-*` branch. It reapplies Expo's coordinated package alignment, then reports the original branch and changed files while deliberately leaving the result uncommitted for review. Vulcanary restores the repository and deletes the draft branch if setup fails; it never pushes or merges the branch automatically.

Prefer fingerprint-scoped suppressions over blanket rule ignores. A single source finding can use a governed inline exception on its own line or the preceding line:

```javascript
// vulcanary:ignore CODE-JS-INNERHTML owner=security@example.com expires=2027-01-31 -- Values are escaped by the shared renderer.
```

The rule ID, owner, ISO expiration date, and meaningful justification are mandatory. Valid exceptions appear in the dashboard Risk Acceptance Register and audit trail. Vulcanary warns during the final 14 days; incomplete or expired annotations fail closed and restore the underlying finding.

## Current capabilities

- Secret patterns: AWS access keys, GitHub tokens, and private keys
- SAST patterns: selected Python and JavaScript execution/XSS sinks plus unsafe Python deserialization
- IaC and CI patterns: root containers, floating base tags, download-to-shell builds, public Terraform ingress or storage ACLs, GitHub Actions `write-all` permissions, mutable action branches, and persisted checkout credentials
- Dependency advisories: npm, Yarn Classic/Berry, pnpm, pinned requirements, Poetry, uv, and PDM lockfile packages queried against OSV
- Conservative reachability context: observed JavaScript/TypeScript and Python imports, including imported direct parents of vulnerable transitive npm packages
- Shortest npm dependency chains with runtime/development parent scope and explicit tooling-path classification
- Read-only remediation recommendations that prefer verified parent or platform upgrades over unscoped transitive overrides
- Contextual remediation priority that keeps advisory severity intact while separating urgent runtime exposure from planned or upstream-monitored tooling findings
- Stable fingerprints and deduplication
- Configurable exclusions and severity gates
- Console, normalized JSON, and SARIF 2.1 output
- A GitHub Actions workflow that uploads results to code scanning
- Multi-repository local dashboard with automatic rescans
- Isolated parent-package and coordinated Expo upgrade evaluation
- Verified dependency, platform, and supported source-fix branches with rollback, project checks, rescanning, and guarded commits
- CycloneDX dependency inventory and change tracking
- Fingerprint-scoped, owned, expiring security exceptions with a local audit trail
- Pull-request dependency admission for denied packages/licenses, lifecycle scripts, non-registry sources, and missing npm integrity
- Permission-gated passive HTTP header and cookie audits
- Normalization of OWASP ZAP, Prowler JSON-OCSF, and generic SARIF 2.1 reports

Dependency scanning sends only package names, ecosystems, and pinned versions to OSV.dev; source code is never uploaded. Successful query and public advisory responses are cached for six hours in the operating system's temporary directory using hashed package identities. The cache never contains repository paths or source, and `VULCANARY_CACHE_DIR` can select a different location. Use `--offline` to disable advisory queries.

Reachability is local static context, not proof of safety. **Import observed** means Vulcanary found an application import of the vulnerable package or an introducing direct parent. **Import not observed** never suppresses or lowers a finding because dynamic imports, build tooling, plugins, and runtime entry points may still execute it.

Exposure context separately correlates findings with route-like source paths and local deployment assets such as Vercel, Netlify, Fly, Serverless, Docker, Terraform, and GitHub Actions configuration. Route-plus-deploy evidence raises remediation priority; missing or partial evidence never labels a finding private, unreachable, or safe.

For transitive npm findings, Vulcanary records the shortest chain from each introducing direct dependency to the vulnerable version. Usage labels distinguish direct application imports, observed runtime parents, development-only parents, and recognizable build/test tooling paths. These labels add context without changing severity or claiming that missing static evidence proves safety.

When OSV publishes fixes for multiple maintained release lines, Vulcanary prefers the lowest patched version in the installed package's current major line. It does not label a fix as a major upgrade merely because a newer-major fix appears first in the advisory record.

Tooling-only transitive findings first receive a compatible lockfile or parent-upgrade evaluation. If one immediate tooling parent remains pinned, Vulcanary can test a **parent-scoped override** in a detached worktree. Lifecycle scripts stay disabled; the advisory must disappear on rescan and configured project checks must pass. Only that exact parent/package/version tuple is then unlocked for the ordinary reviewed fix workflow. Dirty repositories, ambiguous parent chains, skipped verification, global overrides, and unresolved advisories fail closed.

Remediation priority is a deterministic operational score, separate from advisory severity. It combines severity with direct/import evidence, runtime versus tooling context, patched-release availability, and automatic-fix eligibility. The dashboard reports **Urgent**, **High priority**, **Planned**, or **Monitor upstream** while always retaining the scanner's original severity.

The remediation queue can be sorted by contextual priority, original severity, policy deadline, fixability, or repository. Deadline badges keep overdue ownership visible during triage instead of requiring each finding to be opened individually.

## Software bill of materials

Export a CycloneDX 1.5 SBOM alongside scan results:

```powershell
vulcanary . --sbom vulcanary.cdx.json
```

Export the same inventory as SPDX 2.3 JSON when downstream tooling expects SPDX:

```powershell
vulcanary . --spdx vulcanary.spdx.json
```

Export observed dependency vulnerabilities as OpenVEX without claiming that missing static reachability proves safety:

```powershell
vulcanary . --openvex vulcanary.openvex.json
```

The local dashboard provides **Download SBOM**, **Download SPDX**, and **Download VEX** for every watched repository. Supply-chain documents contain package identities, versions, package-manager and direct/transitive properties, advisory relationships, and Vulcanary context. OpenVEX statements mark versions Vulcanary actually observed as `affected`; Vulcanary never manufactures `not_affected` status from absent static imports. These exports exclude source content, absolute repository paths, credentials, and raw command output. The bundled GitHub Actions workflow uploads all three formats with the normalized JSON and SARIF reports.

The dashboard keeps a local dependency-inventory baseline in `~/.vulcanary/dashboard-history.json`. Every subsequent scan reports exact components added and removed since the previous successful scan, including version changes as one removal plus one addition. Use **Inventory changes** on a repository card to review the delta. This history stays on the local machine and is not included in GitHub artifacts or the public Vulcanary repository.

## Pull-request enforcement

The bundled GitHub Actions workflow scans the pull request's base commit with the same Vulcanary version, then gates only findings introduced by the proposed change. New findings produce native workflow annotations at their file and line; findings at or above `.vulcanary.json`'s `fail_on` severity fail the check. Existing findings remain in the normalized and SARIF reports without making every pull request permanently red. Moving an unchanged finding to another line does not reclassify it as new.

For manual CI integration, create a normalized report for the trusted base revision and pass it to the candidate scan:

```powershell
vulcanary . --baseline-json base-vulcanary.json --github-annotations --sarif vulcanary.sarif
```

Malformed or incomplete baseline reports fail closed. The workflow uploads SARIF to GitHub code scanning when its token has `security-events: write`; uploads are skipped for untrusted fork pull requests while local annotations and policy enforcement still run.

### Dependency admission and blocked merges

`dependency-review` compares two checkouts using their committed lockfiles. It never installs or imports a proposed package. Only newly introduced locked package identities are evaluated, so existing debt does not permanently block unrelated pull requests:

```powershell
vulcanary dependency-review . --base path\to\trusted-base --github-annotations --json dependency-review.json
```

The `dependency_policy` configuration can deny exact package names and declared npm licenses, forbid dependencies with install-time lifecycle scripts, forbid Git/file/direct-URL sources, and require npm lockfile integrity digests. The policy is always loaded from the trusted base checkout, so a pull request cannot approve itself by weakening `.vulcanary.json`. Findings fail closed at high severity. The bundled pull-request workflow runs this gate before the ordinary code scan; making the Vulcanary job a required repository check blocks the merge. This is **dependency admission**, not an invisible replacement for `npm install` or `pip install`: Vulcanary does not hook package-manager processes or silently change a developer's machine.

## Import other scanners

Vulcanary can normalize existing scanner output into the same local policy gate, JSON, SARIF, SBOM vulnerability data, and GitHub annotations. The external tools remain optional and run wherever you choose; Vulcanary only reads their JSON reports.

```powershell
vulcanary . --semgrep-json semgrep.json --gitleaks-json gitleaks.json `
  --trivy-json trivy.json --checkov-json checkov.json --zap-json zap.json `
  --prowler-json prowler.ocsf.json --sarif-json other.sarif --sarif vulcanary.sarif
```

Each option can be repeated. Imported paths are constrained to the scanned repository, malformed reports fail closed, and Gitleaks secret values are never retained in Vulcanary output.

Container images are opt-in and report-driven: generate a Trivy image report separately and import it with `--trivy-image-json report.json`, or provide the report path in the dashboard scan form. Vulcanary normalizes the image package inventory and vulnerabilities under the `container` category. It never starts Docker, mounts the Docker socket, pulls an image, contacts a registry, or executes anything from the report.

The local dashboard accepts optional report paths for Semgrep, Gitleaks, Trivy filesystem/images, Checkov, OWASP ZAP, Prowler JSON-OCSF, and generic SARIF 2.1 in the scan form. Imported findings retain their scanner identity and can be filtered by scanner, category, or severity. Report paths stay in memory for rescans and are not written to dashboard history.

Safe synthetic examples live in `examples/reports/` for ZAP, Prowler JSON-OCSF, and SARIF. They contain no real targets, cloud identifiers, secrets, or scan output and can be used to exercise the import UI against a disposable repository.

### Make the pull-request gate enforceable

After the workflow succeeds once, open the repository's **Settings → Rules → Rulesets**, create a branch ruleset targeting the default branch, enable **Require status checks to pass**, and select the Vulcanary `scan` check. Also require pull requests and block force pushes. GitHub controls these repository settings; committing a workflow alone cannot make its check mandatory. Keep an administrator recovery path and test the ruleset with a temporary failing pull request before relying on it.

Other public repositories can call `.github/workflows/security-scan.yml` as a reusable workflow. Consumers should pin both the workflow reference and its required `vulcanary_ref` input to the same full Vulcanary commit SHA.

The included GitHub Actions workflow automatically runs pinned Semgrep Community Edition, Gitleaks, Trivy, and Checkov containers. Source is mounted read-only, temporary reports stay outside the checkout, Semgrep metrics are disabled, Gitleaks output is fully redacted, and no scanner receives the Docker socket. Vulcanary applies one policy gate to all four reports. No scanner account or API token is required.

Every scan can export `--ruleset-manifest vulcanary-ruleset.json`. The canonical manifest lists each built-in rule's identifier, severity, category, supported extensions, detector pattern and flags, and remediation text with a deterministic SHA-256 digest. JSON/SARIF metadata, the dashboard, and CI artifacts carry the same digest so rule changes are reviewable rather than silent.

`--provenance vulcanary-provenance.json` creates an in-toto Statement v1 containing SHA-256 subjects for the generated JSON, SARIF, CycloneDX, SPDX, and ruleset artifacts. The statement explicitly marks itself unsigned; a trusted CI identity or key-backed signer must sign it externally before it should be treated as an attestation. Vulcanary never invents or stores signing keys.

The bundled public-repository workflow follows that boundary by creating a separate, least-privilege attestation job only for pushes to `main`. It downloads the completed scan artifacts and uses GitHub's OIDC-backed `actions/attest` flow to create a keyless Sigstore attestation. Pull-request code never runs in the job holding `id-token` or `attestations` write permissions. Verify a downloaded report with `gh attestation verify <file> --repo OWNER/REPOSITORY`.

## Passive web/API security

Vulcanary can make one non-authenticated GET request to a web target and report HTTPS, HSTS, CSP, clickjacking, MIME-sniffing, referrer-policy, and cookie-attribute gaps:

```powershell
vulcanary web-audit https://staging.example.com `
  --authorize-target staging.example.com --json web-audit.json
```

`--authorize-target` must exactly match the URL hostname. Embedded credentials and cross-host redirects are refused. Public-address resolution is checked before and after the request; private, loopback, link-local, reserved, and otherwise non-public addresses are refused by default. A DNS answer that changes across the request fails closed. This is fail-closed detection of a changed answer, not complete DNS-rebinding prevention: the HTTP client performs its own connection-time lookup, so a rebind inside that window is detected after the request rather than prevented before it. Authorized internal testing is CLI-only and requires both the exact hostname and `--allow-private-target`. This command does not crawl, fuzz, submit forms, authenticate, or exploit anything; it is a passive configuration audit, not a penetration test. For broader authorized testing, run free OWASP ZAP Baseline/API Scan separately and import its JSON with `--zap-json`. Active ZAP scanning intentionally remains outside Vulcanary's automatic workflows because it attacks the target and requires explicit scope and authorization.

## Read-only cloud posture

Vulcanary does not ask for or retain AWS, Azure, GCP, Kubernetes, Microsoft 365, or other cloud credentials. The free Prowler CLI can use an operator's existing read-only provider session and emit JSON-OCSF locally; import that file with `--prowler-json` or through the dashboard. Vulcanary retains the check, severity, provider, region, and resource identity while excluding raw cloud response data.

This provides cloud-posture reporting and policy normalization—not agent-based runtime protection, workload isolation, attack-path analysis, or cloud remediation. Generic `--sarif-json` also creates a subscription-free boundary for compatible SAST, IaC, container, secret, malware, and supply-chain scanners without granting those tools dashboard access.

## Reviewed custom rules

Repositories can place `custom_rules` in `.vulcanary.json`. Custom identifiers must start with `CUSTOM-`; each rule declares a regex pattern, severity, category, remediation, optional dot-prefixed extensions, status, and review fixtures. Draft rules are recorded but never execute. An approved rule must contain at least one matching and one nonmatching fixture, and configuration loading fails closed if the pattern does not satisfy every fixture. Approved rules become part of that repository's canonical ruleset digest.

```json
{
  "custom_rules": [{
    "id": "CUSTOM-UNSAFE-API",
    "title": "Unsafe internal API",
    "pattern": "unsafe_api\\s*\\(",
    "severity": "high",
    "category": "sast",
    "remediation": "Use the validated API wrapper.",
    "extensions": [".py"],
    "status": "approved",
    "tests": {
      "matching": ["unsafe_api(value)"],
      "nonmatching": ["safe_api(value)"]
    }
  }]
}
```

Finding details show deterministic confidence, redacted evidence, reachability, exposure, ownership, deadline, and the recommended remediation path. **Export Markdown ticket**, **Export JSON ticket**, and **Export CSV ticket** create local handoff records that deliberately exclude source content, evidence, credentials, command output, and absolute paths. CSV provides a simple import boundary for common ticket systems without giving Vulcanary access to those services.

GitHub workflows can pass `--github-summary` to append a sanitized severity table and top finding list to the native job summary. The bundled workflows enable it alongside annotations and SARIF; summaries contain repository-relative locations but no evidence, source snippets, credentials, or absolute paths.

## Public accuracy benchmark

`benchmarks/cases.json` contains one synthetic vulnerable fixture and one closely related safe fixture for every built-in deterministic rule. The suite fails when a rule misses its vulnerable case, fires on its safe neighbor, or lacks benchmark coverage. Run `python -m unittest tests.test_benchmark -v`. Passing this benchmark proves the published fixture boundary—not complete detection of every real-world vulnerability—and that limitation is intentional and documented.

## Roadmap

1. **Source-recipe expansion:** add more narrowly reviewed transformations and an optional, explicitly configured AI drafting adapter without weakening deterministic validation gates.
2. **Rule sharing:** add signed, versioned community rule packs on top of the repository-local review fixtures and canonical digest boundary.
3. **Team workflow:** add opt-in notification delivery around the existing source-free Markdown and JSON ticket exports.
4. **Dependency remediation:** add rollback-proven lockfile updates for Yarn, nested pnpm workspaces, Poetry, uv, and PDM, plus API-level compatibility smokes for known high-risk overrides.
5. **Hosted control plane:** only if needed, add authenticated workers, tenant isolation, RBAC, durable audit storage, and explicit source-retention controls without weakening local-first mode.

Vulcanary consumes OSV rather than maintaining a private vulnerability database, preserving advisory identifiers and fixed versions in its normalized findings. Exact Python pins in `requirements*.txt`, direct npm dependencies, and direct root-workspace pnpm dependencies can be upgraded locally when OSV identifies a same-major fix. pnpm uses `--lockfile-only --ignore-scripts`; every manager still requires an isolated branch, security rescan, configured project checks, and an explicit commit. Yarn, nested pnpm workspaces, Poetry, uv, and PDM findings remain read-only until equivalent lockfile rollback and verification coverage is available.

## Security boundaries

The dashboard is a loopback-only local service, not an authenticated multi-user control plane. It rejects non-loopback bind addresses and Host headers, cross-site actions, non-JSON or non-object request bodies, and negative or oversized content lengths. JSON responses disable caching, MIME sniffing, and referrer propagation.

Treat scanned repositories as hostile input. Production workers should run without cloud credentials, with a read-only checkout, CPU/memory/time limits, no Docker socket, and network disabled unless an adapter explicitly needs allow-listed advisory endpoints. Never execute build scripts merely to discover dependencies.

The passive web audit is permitted only for a hostname the operator explicitly affirms they own or are authorized to test. Imported ZAP and Prowler files are treated as untrusted data. Vulcanary parses them without executing embedded content, excludes response bodies and secret values, and never launches ZAP, Prowler, Docker, or a cloud CLI on the user's behalf.

## Public repository

Vulcanary is designed to be published independently of the repositories it scans. Do not commit real scan reports, repository snapshots, `.env` files, access tokens, or organization-specific suppressions. See `SECURITY.md` for responsible disclosure guidance.

Community participation is governed by `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, issue/PR templates, and private vulnerability reporting. The source code remains MIT-licensed. The Vulcanary name and brand assets follow `TRADEMARKS.md` so modified distributions cannot be mistaken for official security releases.
