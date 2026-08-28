# Security policy

## Reporting a vulnerability

Please do not disclose exploitable vulnerabilities in a public issue. Report them privately through GitHub's private vulnerability reporting feature. Include the affected version, reproduction steps, impact, and any suggested remediation.

Do not include live credentials, proprietary source code, or unredacted scan reports. Use synthetic examples whenever possible.

## Safety model

Normal scans treat repositories as untrusted data: Vulcanary reads files without executing repository code or requiring repository credentials, and secret matches are redacted in output.

Remediation is a separate, explicit workflow. Dependency and platform evaluators use detached worktrees, disable package lifecycle scripts, and return sanitized results. Applying a fix requires a clean named Git branch, uses a dedicated `vulcanary/*` branch, rescans the result, and runs only the verification commands explicitly configured by the repository owner. Failed validation restores the original branch and tracked working tree. Vulcanary does not push or merge fixes automatically.

The dashboard binds to loopback by default, sets a restrictive Content Security Policy, accepts state-changing requests only as JSON, and rejects cross-origin or cross-site browser actions. Do not expose the dashboard port through a public proxy.
