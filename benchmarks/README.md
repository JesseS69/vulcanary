# Vulcanary accuracy benchmark

`cases.json` contains one synthetic vulnerable example and one safe neighbor for every built-in deterministic rule. The test suite scans each case in isolation and fails if the target rule misses its vulnerable fixture or fires on its safe fixture.

This benchmark is intentionally narrow: passing it proves fixture behavior, not complete vulnerability detection. New rules must add both fixtures, explain their confidence boundary, and remain source-only—never copy real credentials or proprietary code into this directory.

Run it with `python -m unittest tests.test_benchmark -v`.

## External corpus metrics

`corpora.json` is the source of truth for external validation inputs. Git corpora must use a full immutable commit SHA, and every entry must state `"execution": "never"`: Vulcanary reads source files and expected-result data but never executes corpus code. Downloads are an explicit contributor validation step and never occur during installation, normal scans, offline scans, or the unit suite.

Generate JSON reports with the Vulcanary revisions being compared, then run `python scripts/compare_corpus_metrics.py BASELINE.json CANDIDATE.json COMPARISON.json` from an environment where Vulcanary is installed (or with `src` on `PYTHONPATH`). The comparison records finding, gap, truncation, parse-error, module, call, benchmark, runtime, and optional memory deltas. It also reports added and removed fingerprints and detects fingerprint churn when a stable sink identity receives a different fingerprint.

External corpus scores remain evidence, not targets. Changes should explain both improvements and regressions; they must not add benchmark-specific behavior without a general security rationale.
