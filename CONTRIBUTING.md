# Contributing

Contributions are welcome through pull requests.

## Parser robustness

Repository manifests, source files, CycloneDX documents, and external scanner reports are untrusted input. The deterministic robustness suite mutates every supported dependency format, nested JSON document shapes, adapter schemas, and Python source without invoking package managers or executing scanned code:

```powershell
python -m unittest tests.test_parser_robustness -v
```

The byte mutator uses the fixed seed `0x561CA`. An exposed crash must be retained as a minimal regression fixture or remain reproducible from that seed; changing the seed to make a failure disappear is not an acceptable fix. Dependency discovery may return packages and coverage warnings, while external adapters may return findings or raise `AdapterError`. Raw parser, decoding, indexing, or type exceptions must never cross either public boundary.

1. Use Python 3.11 or newer.
2. Run `python -m unittest discover -s tests -v` before submitting.
3. Add tests for scanner or reporting behavior changes.
4. Use synthetic secrets and vulnerable examples only. Never submit real credentials or proprietary scan data.
5. Explain false-positive and false-negative tradeoffs for new detection rules and add paired fixtures to `benchmarks/cases.json`.
6. Keep remediation deterministic, fail closed on unrecognized shapes, and test preview, application, rollback, and rescan behavior.
7. Follow `CODE_OF_CONDUCT.md`; source code is MIT-licensed while the project marks follow `TRADEMARKS.md`.

Security-sensitive reports belong in private vulnerability reporting rather than public issues.
