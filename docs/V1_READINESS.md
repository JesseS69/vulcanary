# Vulcanary v1.0 readiness gate

This document defines what **v1.0 ready** means for Vulcanary's free, local-first product. It is a release gate, not a list of aspirations. A clean scan is never a security guarantee, experimental dataflow remains outside policy enforcement, and capabilities that require separately installed tools remain opt-in.

## Status vocabulary

| Status | Meaning |
|---|---|
| **Met** | Reproducible evidence exists in the repository or a tagged release workflow. |
| **Partial** | Useful behavior ships, but the stated v1 acceptance evidence is incomplete. |
| **Open** | Required for v1 and not yet satisfied. |
| **Deferred** | Explicitly outside the free local-first v1 scope; absence does not block v1. |

A criterion moves to **Met** only when its evidence is repeatable by another contributor. Green unit tests alone are not sufficient for claims about installers, public releases, external corpora, or operating-system behavior.

## Release blockers

### 1. Trust boundaries and safe defaults

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Ordinary scans never execute repository code or repository-supplied commands. | Tests and inspection cover dependency discovery, AST analysis, report import, and resolved-input ingestion; `verify_commands` remains confined to explicit remediation. |
| **Met** | Malformed repository inputs fail safely. | `tests/test_parser_robustness.py` exercises deterministic byte mutations across supported manifests, nested JSON shapes, external adapters, CycloneDX, and Python source. Independent review measured 800 trials with 25 pre-fix crashes and zero after hardening. |
| **Met** | Secret plaintext never reaches reports or persistent state. | `tests/test_secret_nonpersistence.py` covers console, JSON, SARIF, OpenVEX, ticket exports, receipts, adapters, history findings, and dashboard history using synthetic credentials. |
| **Met** | Dashboard API access is authenticated and browser actions are origin-bound. | All `/api/` routes except minimal `/api/health` require the tab-scoped control token; Host, Origin, `Sec-Fetch-Site`, JSON content type, and 16 KiB request limits are tested. |
| **Met** | The dashboard is local-only by default and documented as unsuitable for public proxying. | Loopback binding, restrictive CSP, token delivery/removal, and the warning in `SECURITY.md`. |
| **Met** | Passive web auditing requires explicit authorization and refuses unsafe targets. | Exact-host authorization, redirect refusal, private-address refusal by default, and pre/post-request DNS checks are tested and documented. |
| **Met** | External executable trust is explicit. | History scanning accepts only an absolute Gitleaks path, runs outside the repository working directory, disables text conversion, and forces redaction. |
| **Partial** | Every supported untrusted-input parser has a retained mutation corpus. | Deterministic coverage exists; add the independently useful deletion, insertion, duplication, astral/surrogate Unicode, brace-corruption, byte-swap, and bounded 50 KiB inflation operators to the permanent suite. |
| **Open** | Resource-exhaustion behavior is bounded for hostile input. | Add explicit maximum document/file sizes or measured safe upper bounds for report imports, SBOM ingestion, dependency manifests, and AST source parsing; prove over-limit input yields a coverage gap or typed error rather than memory exhaustion. |

### 2. Scanner correctness and honest coverage

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Advisory severity is evidence-based. | Withdrawn advisories are excluded; CVSS v3/v4 and source ratings are used; missing evidence becomes `UNKNOWN`, which cannot trip policy gates. |
| **Met** | Aliased advisory records collapse without losing provenance. | Alias-closure tests preserve contributing advisory IDs and legacy fingerprints. |
| **Met** | Fixed-version advice never recommends a version behind the installed release. | Multi-branch fixtures cover Log4j maintenance lines, stable/prerelease ordering, minimal forward upgrades, and the no-newer-fix fallback. |
| **Met** | A clean result is visually distinct from incomplete analysis. | The coverage matrix separates analyzed, incomplete, unsupported, disabled, and not-applicable states; only actionable incomplete states feed the warning headline. |
| **Met** | Native dependency discovery covers the supported manifest families without invoking their toolchains. | npm, PyPI, Go, crates.io, Packagist, RubyGems, NuGet, Maven, and Gradle resolved inputs plus CycloneDX; Maven/Gradle missing-input states are explicit. npm package managers share the npm ecosystem count. |
| **Partial** | Each native ecosystem has canonical valid, malformed, direct/transitive, development/runtime, and known-vulnerable fixtures. | Broad parser and live-OSV evidence exists, but consolidate it into a per-ecosystem compatibility matrix with named fixtures and expected identities. |
| **Met** | Reachability evidence never lowers advisory severity or asserts safety from absence. | Correlation changes triage priority only; unsupported Packagist correlation remains `unknown`; `not_observed` includes an explicit uncertainty reason. |
| **Open** | Every scanner and importer emits a machine-readable incomplete-analysis signal when it skips recognized input. | Audit silent malformed-manifest paths that currently return no packages, and normalize their warnings into the coverage matrix. |
| **Open** | Public format contracts are versioned and compatibility-tested. | Pin normalized JSON, SARIF, CycloneDX, SPDX, OpenVEX, ruleset-manifest, receipt, and experimental-report schemas with golden fixtures and documented compatibility rules. |

### 3. Reliability and performance

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Full tests and an offline self-scan pass from an installed wheel on Linux, macOS, and Windows. | `.github/workflows/free-tier-quality.yml` runs Python 3.11 and 3.13 on all three operating systems. |
| **Met** | Experimental dataflow has independent module, call, depth, and wall-time budgets, and surfaces every exhausted global limit. | Dataflow reports include configured budgets, observed counts, truncation identities, parse errors, and categorized unresolved constructs. |
| **Met** | Dataflow optimization cannot disguise lost work as a speedup. | Corpus comparisons diff exposure fingerprints plus exact gap and truncation identity sets and record analyzed-call counts. |
| **Partial** | Representative external corpora have committed, reproducible baselines. | BenchmarkPython and external Python runtime baselines exist; add pinned acquisition instructions and equivalent external corpora alongside each future Java, Go, Ruby, or PHP syntax engine. |
| **Open** | Large-repository runtime and memory budgets are defined and measured. | Select small, medium, and monorepo-scale public corpora; publish cold/warm runtime, peak memory, files analyzed, and all limit records on supported operating systems. |
| **Open** | Interrupted and partially failing scans preserve configured repositories and prior durable state. | Add fault-injection tests for one repository failing while others succeed, interrupted atomic writes, corrupt history recovery, and monitor restart. |
| **Open** | Dashboard state remains bounded over long-running monitoring. | Define retention/compaction limits and soak-test scan history, receipts, resolved findings, and web-audit history. |

### 4. Installation, upgrade, and release integrity

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Version is consistent across source metadata, tag, installed wheel, and release. | Release verification checks `pyproject.toml`, `version.py`, tag target, and clean-environment CLI output. |
| **Met** | Release artifacts are immutable and independently verifiable. | Tagged workflow publishes wheel, source archive, installer, uninstaller, and `SHA256SUMS.txt`; the manifest covers the other four assets with basename-only SHA-256 entries. |
| **Met** | Windows installation and removal preserve user data by default. | The release workflow exercises install, upgrade, configuration export/import, backup/restore, and uninstall. Purging local data requires an explicit flag. |
| **Met** | A package reinstall preserves local configuration. | `upgrade-preservation` compares application configuration byte-for-byte after reinstall in an isolated home directory. |
| **Open** | Upgrade compatibility is proven across a declared support window. | Test sequential upgrades from at least the oldest supported pre-v1 release and the immediately previous release, including configuration, history, suppressions, fingerprints, and receipts. Publish the support-window policy. |
| **Open** | Release provenance has a documented verification path. | CI emits keyless GitHub attestations for scan artifacts; document consumer verification and decide whether release distributions also require attestations before v1. |
| **Open** | Release rollback is rehearsed. | Document and test how to withdraw a broken release, restore the prior package, preserve user data, and communicate checksum/tag status without rewriting an immutable release. |

### 5. User experience and documentation

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | A new user can install, run a scan, interpret coverage, and open the dashboard without private assistance. | README quick start, Windows installer path, CLI examples, synthetic dashboard screenshot, and inline coverage explanations. |
| **Met** | Current limitations and authorization boundaries are public. | README documents local/CI `.env` asymmetry, namespace-only reachability, dataflow limits, passive web scope, cloud/report ingestion boundaries, and remediation command execution. |
| **Partial** | Dataflow capabilities are quickly retrievable. | The information is accurate but dense; replace the long paragraph with a concise resolves/gaps/silent table while retaining benchmark and safety detail. |
| **Open** | Every warning includes a next action. | Audit CLI, JSON, and dashboard warnings for a stable code, affected path/capability, concise reason, and remediation or documentation link. |
| **Open** | Accessibility is verified. | Keyboard-only dashboard pass, visible focus, semantic labels, contrast check, reduced-motion behavior, and screen-reader smoke test using only synthetic repository data. |
| **Open** | CLI behavior is stable and documented. | Command/option snapshot tests, exit-code contract, machine-readable error contract, deprecation policy, and shell-completion decision. |

### 6. Project governance and support

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Security reports have a private channel and handling guidance. | `SECURITY.md` defines supported versions, private reporting, safe reproductions, and trust boundaries. |
| **Met** | Community and support expectations are explicit. | `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, issue/PR templates, MIT license, and trademark policy are public. |
| **Open** | Dependency and action update policy is documented. | Define review cadence and pinning policy for GitHub Actions, build tooling, scanner container images, and the vendored CVSS implementation. |
| **Open** | A release checklist requires independent verification. | Require clean main, version consistency, full CI, installed-wheel smoke, checksum verification, release metadata, branch cleanup, self-scan, and a reviewer who did not author the change. |
| **Open** | A vulnerability-response rehearsal has been completed. | Run a synthetic private report through triage, patch, advisory/release preparation, notification, and postmortem without publishing a live secret. |

## Explicitly deferred from free local-first v1

These capabilities require separate product, trust, cost, or authorization decisions. They are not implied by a v1 label:

- Hosted runtime or cloud workload protection, managed accounts, organization tenancy, or an uptime SLA.
- Automatic purchase or use of paid vulnerability, exploitability, or threat-intelligence feeds.
- Active penetration testing, crawling, credentialed target access, or automated exploitation.
- Accepting or storing cloud-provider credentials.
- Automatically pushing, opening, approving, or merging remediation pull requests in scanned repositories.
- Treating experimental dataflow output as a policy gate, SLA clock, ordinary finding, or remediation trigger.
- Bundling or silently downloading Gitleaks, ZAP, Semgrep, Trivy, Checkov, Prowler, package managers, or language toolchains.

## Standing merge gates through v1

Every intervening pull request must preserve these properties:

1. No scanned code executes during scanning or analysis.
2. No plaintext secret reaches output, logs, receipts, tickets, or dashboard history.
3. Existing finding and exposure fingerprints do not churn without an explicit migration.
4. Analysis limits, parser failures, and unsupported constructs are surfaced rather than presented as clean.
5. Experimental dataflow remains structurally isolated from policy and remediation.
6. Corpus comparisons record precision, recall, false-positive rate, TPR−FPR, runtime, workload, gaps, truncations, and fingerprint changes when applicable.
7. New network feeds, external executables, active testing, cloud credentials, work outside Vulcanary, or remediation PR creation against scanned repositories require a separate authorization decision.

## v1 release decision

Vulcanary may be tagged v1.0 only when every **Open** release blocker above is **Met** or explicitly moved to **Deferred** with a written rationale and user-visible limitation. The release candidate must remain unchanged while its artifacts, upgrade path, documentation, and public security scan are independently verified. Any code change after verification creates a new candidate and restarts the affected checks.
