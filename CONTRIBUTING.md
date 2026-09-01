# Contributing

Contributions are welcome through pull requests.

1. Use Python 3.11 or newer.
2. Run `python -m unittest discover -s tests -v` before submitting.
3. Add tests for scanner or reporting behavior changes.
4. Use synthetic secrets and vulnerable examples only. Never submit real credentials or proprietary scan data.
5. Explain false-positive and false-negative tradeoffs for new detection rules and add paired fixtures to `benchmarks/cases.json`.
6. Keep remediation deterministic, fail closed on unrecognized shapes, and test preview, application, rollback, and rescan behavior.
7. Follow `CODE_OF_CONDUCT.md`; source code is MIT-licensed while the project marks follow `TRADEMARKS.md`.

Security-sensitive reports belong in private vulnerability reporting rather than public issues.
