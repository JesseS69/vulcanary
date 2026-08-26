# Security policy

## Reporting a vulnerability

Please do not disclose exploitable vulnerabilities in a public issue. Report them privately through GitHub's private vulnerability reporting feature. Include the affected version, reproduction steps, impact, and any suggested remediation.

Do not include live credentials, proprietary source code, or unredacted scan reports. Use synthetic examples whenever possible.

## Scanner safety model

Repositories are treated as untrusted data. Vulcanary reads files but does not execute repository code, install repository dependencies, invoke build scripts, or require repository credentials. Secret matches are redacted in output.
