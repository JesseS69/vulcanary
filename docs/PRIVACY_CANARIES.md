# Synthetic privacy canaries

This experimental adapter checks explicitly supplied synthetic exports for one
generated marker. It does not collect device logs, inspect a clipboard, contact
an endpoint, execute an application, or establish that a candidate is private.
It is separate from scanner gates, SLA records, and candidate capability passes.

Generate a private registry:

```text
python -m vulcanary.privacy_canaries create --private-output private-canary.json
```

Creation reports NOT_RUN. In a separately authorized disposable test, use the
registry's marker as synthetic data. Keep the registry private and out of exports.
Do not substitute a real key or credential. Supply only exports from that test:

```text
python -m vulcanary.privacy_canaries scan --canary private-canary.json --file synthetic.log --category device-log --manifest-sha256 YOUR_64_CHARACTER_MANIFEST_DIGEST --authorize-synthetic-exports --output new-review-package
```

Categories describe the operator's collection method: device-log, browser-log,
crash-report, analytics-export, url-capture, clipboard-export, temporary-file.
Neither the category nor the manifest reference authenticates collection or proves
which installed application produced the file. This report cannot automatically
close a device requirement in a candidate report.

PASS means no exact match in the supplied stable bytes, for the four supported
representations: literal, lowercase hexadecimal, standard base64, and uppercase
percent encoding. It does not cover missing exports, screenshots, transformed or
truncated values, alternate encodings, app-switcher previews, or unsampled events.
FAIL means a marker was found. BLOCKED means the file was unavailable, changed,
oversize, or unsupported. A FAIL remains visible when another file is BLOCKED;
counts and coverage_complete preserve the partial coverage.

The adapter reads at most 16 explicitly named regular, non-symlink files, at most
8 MiB each. It records at most 100 matches per file; exceeding that cap remains
FAIL with incomplete coverage. Reduce or split exports deliberately and rerun to
investigate a limit. Never interpret a refused input as clean.

The new output directory contains report.json, reviewer.md, and unsigned
checksums.json. Reports contain ordinal file IDs, file hashes, byte offsets and
encoding names, never paths, snippets, marker values, or encoded marker values.
Retain a private mapping from ordinal IDs to original files for reproduction.
File hashes identify supplied bytes; unsigned checksums do not authenticate them.
Exit codes are 0 for PASS, 1 for a detected marker, 2 for blocked/error.

Inputs stay untouched. No automatic cleanup deletes supplied exports or registries.
Remove disposable test data through the test owner's explicit cleanup procedure.
