# Vulcanary accuracy benchmark

`cases.json` contains one synthetic vulnerable example and one safe neighbor for every built-in deterministic rule. The test suite scans each case in isolation and fails if the target rule misses its vulnerable fixture or fires on its safe fixture.

This benchmark is intentionally narrow: passing it proves fixture behavior, not complete vulnerability detection. New rules must add both fixtures, explain their confidence boundary, and remain source-only—never copy real credentials or proprietary code into this directory.

Run it with `python -m unittest tests.test_benchmark -v`.
