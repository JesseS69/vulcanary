# CLI compatibility contract

The installed `vulcanary` command and `python -m vulcanary` share the same entry
point. A repository path invokes a scan; command names select the documented
subcommands. `--help` is local and does not run scans or contact services.
`tests/test_cli_contract.py` pins every command's option/positional names, key
safety defaults, help dispatch, representative exits and source-free diagnostics.

## Exit codes

| Command/result | Exit |
|---|---|
| Scan completes without findings meeting the configured fail threshold | 0 |
| Scan has policy-blocking findings | 1 |
| Dependency review has admission findings; web audit meets its fail threshold | 1 |
| `--no-fail` on scan, dependency review or web audit | Suppresses finding-based 1 only |
| Incomplete advisory lookup or other coverage warning without blocking findings | 0; inspect report warnings/coverage, not just the exit code |
| Experimental dataflow completes, including exposures or surfaced analysis limits | 0; never a policy gate |
| `status` finds the service stopped; `stop` finds it still running | 1 |
| `update-check` finds a newer release | 1; no installation occurs |
| Successful service/configuration command, or `--help` | 0 |
| Invalid arguments, unavailable input, handled operational/export failure, or stale OpenVEX refusal | 2, even with `--no-fail` |

Signals, interpreter startup errors and unexpected programming failures are not
mapped into this contract. Existing warnings do not become new gates. An exit of
zero is not a security guarantee or proof of complete analysis. Output files may
already have been written before a later operation fails; exports are not a
multi-file transaction.

## Machine-readable fatal errors

Opt in with a **leading global prefix**, before the command or repository path:

```text
vulcanary --errors-json ./my-service --offline
vulcanary --errors-json dataflow-prototype ./my-service
vulcanary --errors-json dashboard --port invalid
```

Each handled fatal error emits one JSON line on stderr:

```json
{"schema":"vulcanary.cli-error.v1","code":"invalid_arguments","message":"Invalid command arguments.","action":"Run this command with --help and check required options and value types.","exit_code":2}
```

The prefix does not change stdout, successful reports, policy, warning output or
their schemas. Stderr can contain ordinary warning lines before the fatal JSON
record; consumers should select a JSON object with this schema rather than parse
the entire stream as one document. `--errors-json` is not accepted after a command
and is not removed from option values. Use `--` or a relative path prefix for a
repository whose name starts with a dash.

Messages and actions are static: no raw exception text, rejected argument values,
source excerpts, filenames or credentials are interpolated into fatal diagnostics.
Human-readable mode uses the same safe record as `error [code]: ... Next: ...`.
This intentionally changes legacy free-form error prose and removes argparse's
value-echoing usage errors; human prose was not a supported parsing interface.
Successful service launch still intentionally displays the local authorization
URL when requested; this is not a general stdout redaction mode.

The v1 code vocabulary is `invalid_arguments`, `repository_unavailable`,
`configuration_invalid`, `report_import_failed`, `dataflow_failed`,
`config_transfer_failed`, `web_audit_failed`, `dependency_review_failed`,
`service_failed`, `update_check_failed`, `stale_openvex`, `baseline_invalid`,
`summary_destination_missing`, and `operation_failed`. Broad handled I/O, type,
value, runtime and interactive EOF failures use the last code when no narrower
boundary applies. Unexpected programming exceptions are not swallowed.

## Compatibility and deprecation

Existing command/option names, positional meaning, required arguments, safety
defaults and exit semantics are compatibility surfaces. Changes require explicit
release notes and regression-test updates, not silent snapshot regeneration.
Before removal or incompatible behavior, announce deprecation for at least two
minor releases and provide a replacement/migration example. Security fixes may
bypass that interval with an explicit compatibility notice and rationale.

The error schema is independent of scan and experimental dataflow schemas. New
optional fields are additive; removal, type/meaning changes, required fields, or
new code enum members require a new error schema version. Human prose and argparse
help layout may change across Python versions; parse structured records instead.

Shell completion is deferred from v1: no generated completion scripts or third-party
runtime dependencies are bundled. `--help` remains the authoritative local option
reference. This is a documented scope decision, not a claim completion is tested.
