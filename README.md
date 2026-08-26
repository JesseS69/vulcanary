<p align="center"><img src="src/vulcanary/dashboard_assets/vulcanary-logo.png" alt="Vulcanary canary and forge hammer logo" width="128"></p>

# Vulcanary

Vulcanary is a local-first application security scanner inspired by the developer workflow of platforms such as Wiz and Aikido. It scans checked-out source code for secrets, risky code patterns, and insecure infrastructure-as-code, then turns every result into one finding format that can be used locally or in CI.

It is intentionally a foundation, not a claim of parity with a commercial CNAPP. The architecture is designed so mature engines such as Semgrep, Trivy, Gitleaks, OSV-Scanner, and Checkov can be added as adapters while policy, deduplication, suppression, reporting, and ownership remain centralized.

## Quick start

Python 3.11 or newer is required.

```powershell
cd vulcanary
python -m vulcanary ..\CabinScout
```

For an installed command:

```powershell
python -m pip install -e .
vulcanary path\to\repository --json findings.json --sarif findings.sarif
```

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

The dashboard runs only on `127.0.0.1` by default. It provides repository summaries, severity distribution, searchable findings, and remediation details. Scanned source and findings remain on the local machine.

## Configuration

Copy `.vulcanary.example.json` to `.vulcanary.json` in the repository being scanned:

```json
{
  "fail_on": "high",
  "exclude": ["fixtures/**"],
  "ignored_rules": ["CODE-JS-INNERHTML"],
  "ignored_fingerprints": [],
  "max_file_bytes": 1000000
}
```

Prefer fingerprint-scoped suppressions over blanket rule ignores. A single source finding can also be suppressed on its own line or the preceding line with `// vulcanary:ignore RULE-ID`.

## What the MVP covers

- Secret patterns: AWS access keys, GitHub tokens, and private keys
- SAST patterns: selected Python and JavaScript execution/XSS sinks
- IaC patterns: root containers and public Terraform ingress
- Dependency advisories: pinned npm and Python dependencies queried against OSV
- Stable fingerprints and deduplication
- Configurable exclusions and severity gates
- Console, normalized JSON, and SARIF 2.1 output
- A GitHub Actions workflow that uploads results to code scanning

Dependency scanning sends only package names, ecosystems, and pinned versions to OSV.dev; source code is never uploaded. Use `--offline` to disable advisory queries.

## Production roadmap

1. **Scanner adapters:** ingest Semgrep (SAST), Gitleaks (secrets), OSV-Scanner or Trivy (SCA), and Checkov (IaC/container) JSON. Pin engine and ruleset versions.
2. **Reachability and context:** correlate vulnerable packages with imports, exposed routes, runtime assets, and internet exposure to reduce noise.
3. **Service inventory:** connect repositories, owners, deploys, cloud resources, images, SBOMs, and findings in a graph-backed data model.
4. **Workflow:** add fingerprint-scoped suppressions with expiry, assignment, SLA tracking, notifications, and ticket/PR integrations.
5. **Platform:** authenticated API, job queue, isolated ephemeral scan workers, Postgres, object storage, RBAC, audit log, and tenant isolation.
6. **Supply-chain controls:** generate CycloneDX/SPDX SBOMs, scan lockfiles and container images, sign attestations, and enforce policies at merge/deploy time.

The next dependency milestone is broader lockfile coverage and advisory caching. Vulcanary consumes OSV rather than maintaining a private vulnerability database, preserving advisory identifiers and fixed versions in its normalized findings.

## Security boundaries

Treat scanned repositories as hostile input. Production workers should run without cloud credentials, with a read-only checkout, CPU/memory/time limits, no Docker socket, and network disabled unless an adapter explicitly needs allow-listed advisory endpoints. Never execute build scripts merely to discover dependencies.

## Public repository

Vulcanary is designed to be published independently of the repositories it scans. Do not commit real scan reports, repository snapshots, `.env` files, access tokens, or organization-specific suppressions. See `SECURITY.md` for responsible disclosure guidance.
