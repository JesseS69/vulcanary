"""Source-free CLI diagnostics. Never interpolate argv or exception text."""
from __future__ import annotations

import argparse
from contextvars import ContextVar
import json
import sys


JSON_ERRORS: ContextVar[bool] = ContextVar("cli_json_errors", default=False)
ERRORS = {
    "invalid_arguments": ("Invalid command arguments.", "Run this command with --help and check required options and value types."),
    "repository_unavailable": ("Repository directory is unavailable.", "Check the repository path and directory permissions, then retry."),
    "configuration_invalid": ("Vulcanary configuration could not be loaded.", "Check the configuration file's JSON, field types and read permissions."),
    "report_import_failed": ("External report could not be imported.", "Check the selected report format, JSON structure, size and read permissions."),
    "dataflow_failed": ("Experimental dataflow analysis failed.", "Check the analysis budgets, input paths and output permissions, then retry."),
    "config_transfer_failed": ("Configuration transfer failed.", "Check the backup format and file permissions; preserve the existing configuration before retrying."),
    "web_audit_failed": ("Passive web audit failed.", "Check the URL, exact authorized hostname, network access and target restrictions."),
    "dependency_review_failed": ("Dependency review failed.", "Check both checkout paths and the dependency admission configuration."),
    "service_failed": ("Local service operation failed.", "Check local configuration and port availability, then retry the command."),
    "update_check_failed": ("Update check failed.", "Check network access to GitHub and retry; nothing was installed."),
    "stale_openvex": ("Existing OpenVEX output was not changed.", "Choose a fresh output path to avoid mistaking stale output for this scan."),
    "baseline_invalid": ("Baseline report could not be read.", "Supply a readable Vulcanary normalized JSON report as the baseline."),
    "summary_destination_missing": ("GitHub summary destination is not configured.", "Set GITHUB_STEP_SUMMARY or omit --github-summary."),
    "operation_failed": ("Command could not complete.", "Check input formats, file permissions and output destinations, then retry. Some outputs may already exist."),
}


def fail(code: str) -> int:
    message, action = ERRORS[code]
    if JSON_ERRORS.get():
        print(json.dumps({"schema": "vulcanary.cli-error.v1", "code": code,
                          "message": message, "action": action, "exit_code": 2}), file=sys.stderr)
    else:
        print(f"error [{code}]: {message} Next: {action}", file=sys.stderr)
    return 2


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's message can contain a credential supplied as an option value.
        fail("invalid_arguments")
        raise SystemExit(2)
