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

Current tally: **34 Met / 4 Partial / 5 Open** across **43 release criteria**.
The status-vocabulary rows above are definitions, not additional criteria.

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
| **Met** | Resource-exhaustion behavior is bounded for hostile input. | Source reads have a 10 MB hard ceiling, repository configuration a 1 MB ceiling, dependency manifests and CycloneDX inputs a 32 MiB ceiling, and external reports a 64 MiB ceiling. Bounded reads occur at parser entry; tests prove over-limit input yields a surfaced dataflow limit, dependency coverage warning, or typed error before parsing. |

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
| **Met** | Every scanner and importer emits a machine-readable incomplete-analysis signal when it skips recognized input. | Invalid or unreadable native manifests emit path-specific unresolved-input records that feed `dependency: gap` coverage rows; missing npm, Cargo, Composer, and Bundler locks are explicit when their manifests declare dependencies; CycloneDX warnings, adapter errors, and dataflow parse/limit records retain their typed public contracts. Tests distinguish malformed, unresolved, and legitimately empty inputs. |
| **Met** | Public format contracts are versioned and compatibility-tested. | `docs/REPORT_CONTRACTS.md` defines compatibility and legacy receipt v1; golden exporter fixtures pin fingerprints and seals. Mandatory CI validates SARIF, CycloneDX, SPDX, and OpenVEX against hash-pinned official schemas offline, and local schemas cover normalized JSON, rulesets, receipts, and independently versioned experimental dataflow. |

### 3. Reliability and performance

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Full tests and an offline self-scan pass from an installed wheel on Linux, macOS, and Windows. | `.github/workflows/free-tier-quality.yml` runs Python 3.11 and 3.13 on all three operating systems. |
| **Met** | Experimental dataflow has independent module, call, depth, and wall-time budgets, and surfaces every exhausted global limit. | Dataflow reports include configured budgets, observed counts, truncation identities, parse errors, and categorized unresolved constructs. |
| **Met** | Dataflow optimization cannot disguise lost work as a speedup. | Corpus comparisons diff exposure fingerprints plus exact gap and truncation identity sets and record analyzed-call counts. |
| **Partial** | Representative external corpora have committed, reproducible baselines. | BenchmarkPython and external Python runtime baselines exist; add pinned acquisition instructions and equivalent external corpora alongside each future Java, Go, Ruby, or PHP syntax engine. |
| **Open** | Large-repository runtime and memory budgets are defined and measured. | Select small, medium, and monorepo-scale public corpora; publish cold/warm runtime, peak memory, files analyzed, and all limit records on supported operating systems. |
| **Met** | Interrupted and partially failing scans preserve configured repositories and prior durable state. | State-recovery, monitor-lifecycle and state-bounds tests cover partial scans, startup retry, active monitor stop/restart, failed writes, subprocess exit, config/token and receipt continuity, corrupt history recovery, in-memory rollback, stale writers and startup/shutdown overlap. `docs/STATE_RECOVERY.md` names uncooperative writers and power-loss limits. |
| **Met** | Dashboard state remains bounded over long-running monitoring. | `docs/STATE_RETENTION.md` defines existing collection caps and a 32 MiB retained-document ceiling without deleting continuity to fit. State-bounds tests cover retention, seals and capacity refusal; the repeatable 600-scan synthetic soak records memory, latency and retained bytes in `benchmarks/state-soak-0.64.json`. Transient scanner memory and monorepo performance are separate open work. |

### 4. Installation, upgrade, and release integrity

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Version is consistent across source metadata, tag, installed wheel, and release. | Release verification checks `pyproject.toml`, `version.py`, tag target, and clean-environment CLI output. |
| **Met** | Release artifacts are immutable and independently verifiable. | Tagged workflow publishes wheel, source archive, installer, uninstaller, and `SHA256SUMS.txt`; the manifest covers the other four assets with basename-only SHA-256 entries. |
| **Met** | Windows installation and removal preserve user data by default. | The release workflow exercises install, upgrade, configuration export/import, backup/restore, and uninstall. Purging local data requires an explicit flag. |
| **Met** | A package reinstall preserves local configuration. | `upgrade-preservation` compares application configuration byte-for-byte after reinstall in an isolated home directory. |
| **Met** | Upgrade compatibility is proven across a declared support window. | `docs/UPGRADES.md` declares 0.60.0–0.65.0 endpoint coverage for the 0.66 candidate. Hash-pinned installed-wheel rehearsals check direct/sequential upgrades, configuration/token, suppression data, fingerprints, first-seen, acknowledgements and sealed receipts; mandatory CI runs them on three operating systems. Not exhaustive across all hand-edited state or intermediate versions. |
| **Open** | Release provenance has a documented verification path. | CI emits keyless GitHub attestations for scan artifacts; document consumer verification and decide whether release distributions also require attestations before v1. |
| **Met** | Release rollback is rehearsed. | `scripts/rehearse_upgrade.py` reinstalls actual old wheels and checks retained state/proofs after rewriting. `docs/UPGRADES.md` covers stopped-process backups, known-good packages, release withdrawal communication and immutable checksum/tag handling; no public release is withdrawn by the test. |

### 5. User experience and documentation

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | A new user can install, run a scan, interpret coverage, and open the dashboard without private assistance. | README quick start, Windows installer path, CLI examples, synthetic dashboard screenshot, and inline coverage explanations. |
| **Met** | Current limitations and authorization boundaries are public. | README documents local/CI `.env` asymmetry, namespace-only reachability, dataflow limits, passive web scope, cloud/report ingestion boundaries, and remediation command execution. |
| **Partial** | Dataflow capabilities are quickly retrievable. | The information is accurate but dense; replace the long paragraph with a concise resolves/gaps/silent table while retaining benchmark and safety detail. |
| **Met** | Every warning includes a next action. | `docs/WARNINGS.md` maps dependency, state, history, evaluation, experimental gap/limit/parse and OpenVEX warnings to code, resource/capability, message and action. Diagnostic and VEX tests cover machine-readable export timing, stale-output refusal, exception/source redaction and retained identities; schema tests require guidance on experimental warnings. Fatal CLI/usage errors follow the separate CLI-contract criterion. |
| **Open** | Accessibility is verified. | Keyboard-only dashboard pass, visible focus, semantic labels, contrast check, reduced-motion behavior, and screen-reader smoke test using only synthetic repository data. |
| **Met** | CLI behavior is stable and documented. | `docs/CLI_CONTRACT.md` and `tests/test_cli_contract.py` pin command/option names, key defaults, exit semantics, source-free opt-in JSON errors, and deprecation rules. Offline schema checks enforce the separate error envelope and code vocabulary. Shell completion is explicitly deferred; warnings and experimental results do not become new gates. |

### 6. Project governance and support

| Status | Criterion | Required evidence |
|---|---|---|
| **Met** | Security reports have a private channel and handling guidance. | `SECURITY.md` defines supported versions, private reporting, safe reproductions, and trust boundaries. |
| **Met** | Community and support expectations are explicit. | `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, issue/PR templates, MIT license, and trademark policy are public. |
| **Open** | Dependency and action update policy is documented. | Define review cadence and pinning policy for GitHub Actions, build tooling, scanner container images, and the vendored CVSS implementation. |
| **Met** | A release checklist requires independent verification. | `docs/RELEASE_CHECKLIST.md` requires clean main, version consistency, full CI, installed-wheel and upgrade smoke, checksum verification, release metadata, branch cleanup, self-scan, evidence records and a reviewer who did not author the candidate. It is a gate, not a claim the current candidate has already passed review. |
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
