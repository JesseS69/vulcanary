# Actionable warnings

Dependency diagnostics are additive: legacy `dependency_warning` strings and
unresolved-input discovery strings remain available. Dashboard repository
`health.warnings` and normalized-report `policy.warnings` contain stable `code`,
`message`, `path`, `capability`, and `action` fields. CLI stderr and the dashboard
diagnostics panel show the action. No finding identity, severity or gate changes.

| Code | Meaning / action |
|---|---|
| `dependency_input_too_large` | Human-readable MiB plus raw `actual_bytes`/`limit_bytes`; split scan inputs or provide a smaller resolved inventory. |
| `dependency_input_invalid` | Regenerate/check encoding and structure with a trusted package manager. |
| `dependency_version_unresolved` | Supply exact resolved versions, never guess a version from a range. |
| `dependency_input_unresolved` | Supply supported resolved input; fallback for unresolved input kinds. |
| `advisory_lookup_unavailable` | Restore OSV access and retry; missing results are not safety evidence. |
| `openvex_no_statements` | No VEX output; use normalized JSON when there are no dependency vulnerability statements. |
| `history_scan_failed` | Check repository access and trusted absolute Gitleaks path, then retry; retained exposures are stale. |
| `dataflow_*` | Review unsupported paths manually, fix unreadable/unparseable inputs or raise the specifically named budget. Raising depth does not resolve recursion. |
| `dependency_coverage_incomplete` | Evaluation summary lacks per-input details; supply resolved input and retry. |

State persistence and rescan failures already expose code/message/action records;
their affected resource is the local history document or explicit `repository_path`.
See [state recovery](STATE_RECOVERY.md) for those actions. Warning content and paths
may identify private repositories and must not be published without review.

## Locations and compatibility

OpenVEX skip warnings are collected before normalized JSON and SARIF are written,
including when an existing VEX output causes exit 2. Existing files remain untouched.
The dashboard retains HTTP 422 and legacy `code: no_vex_statements`, adding the
common `warnings` array; authenticated downloads show its next action.

History status retains `state` and `error`, adding `warnings` with the repository
path. Messages deliberately omit external-tool exception text, and prior exposures
survive. The diagnostic panel displays the action and marks health Attention.

Experimental reports optionally include top-level `warnings`. Original gaps,
truncations, parse counts, budgets, exposure identities and `policy_effect: none`
are unchanged. Parse guidance includes file paths but never offending source text.
The dataflow CLI prints the complete JSON report; the dashboard still does not
import or evaluate experimental dataflow. No promotion into gates is implied.

Remediation evaluation results retain legacy warning strings and add structured
guidance. The dashboard shows warnings from the last evaluation in Diagnostics.
These explain incomplete evaluation; they do not alter evaluation status or authorize
applying a fix. Fatal CLI errors and usage errors follow the separate
[CLI contract](CLI_CONTRACT.md), not this warning envelope.

Tests cover skipped exports including stale outputs, authenticated API errors,
external error redaction, retained history exposures, mocked evaluations, parse
redaction, budget guidance and unchanged analysis results. Existing raw dependency
summary strings remain for compatibility; new stderr output uses structured guidance.
