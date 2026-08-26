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

## Configuration

Copy `.vulcanary.example.json` to `.vulcanary.json` in the repository being scanned:

```json
{
  "fail_on": "high",
  "exclude": ["fixtures/**"],
  "ignored_rules": ["CODE-JS-INNERHTML"],
  "max_file_bytes": 1000000
}
```

Suppressions are rule-level in this MVP. A production version should add reviewed, expiring suppressions tied to a fingerprint and approver rather than allowing permanent blanket ignores.

## What the MVP covers

- Secret patterns: AWS access keys, GitHub tokens, and private keys
- SAST patterns: selected Python and JavaScript execution/XSS sinks
- IaC patterns: root containers and public Terraform ingress
- Stable fingerprints and deduplication
- Configurable exclusions and severity gates
- Console, normalized JSON, and SARIF 2.1 output
- A GitHub Actions workflow that uploads results to code scanning

## Production roadmap

1. **Scanner adapters:** ingest Semgrep (SAST), Gitleaks (secrets), OSV-Scanner or Trivy (SCA), and Checkov (IaC/container) JSON. Pin engine and ruleset versions.
2. **Reachability and context:** correlate vulnerable packages with imports, exposed routes, runtime assets, and internet exposure to reduce noise.
3. **Service inventory:** connect repositories, owners, deploys, cloud resources, images, SBOMs, and findings in a graph-backed data model.
4. **Workflow:** add fingerprint-scoped suppressions with expiry, assignment, SLA tracking, notifications, and ticket/PR integrations.
5. **Platform:** authenticated API, job queue, isolated ephemeral scan workers, Postgres, object storage, RBAC, audit log, and tenant isolation.
6. **Supply-chain controls:** generate CycloneDX/SPDX SBOMs, scan lockfiles and container images, sign attestations, and enforce policies at merge/deploy time.

The highest-value next step is dependency scanning from lockfiles. Do not build a private vulnerability database first: consume OSV/NVD/vendor feeds through maintained scanners and preserve their advisory identifiers and fix versions in the normalized model.

## Security boundaries

Treat scanned repositories as hostile input. Production workers should run without cloud credentials, with a read-only checkout, CPU/memory/time limits, no Docker socket, and network disabled unless an adapter explicitly needs allow-listed advisory endpoints. Never execute build scripts merely to discover dependencies.

## Public repository

Vulcanary is designed to be published independently of the repositories it scans. Do not commit real scan reports, repository snapshots, `.env` files, access tokens, or organization-specific suppressions. See `SECURITY.md` for responsible disclosure guidance.
