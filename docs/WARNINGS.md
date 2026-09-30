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
| `openvex_no_statements` (stderr) | No VEX output; use normalized JSON when there are no dependency vulnerability statements. |

State persistence and rescan failures already expose code/message/action records;
their affected resource is the local history document or explicit `repository_path`.
See [state recovery](STATE_RECOVERY.md) for those actions. Warning content and paths
may identify private repositories and must not be published without review.

The v1-wide warning criterion remains **Partial**: OpenVEX's skipped-export signal
is stderr-only, and history-scanner/experimental analysis statuses still use their
separate schemas rather than this common record. This batch standardizes dependency
and state guidance, not every diagnostic in the product. Keep gap categories intact
when unifying those remaining surfaces; do not hide them to make warnings quieter.
