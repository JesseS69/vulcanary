# v0.67.0 release notes

This release introduces an experimental security-testing workflow separate from
ordinary scanning and policy gates. Register a synthetic Python source fixture,
run the built-in static-analysis adapter, and export sanitized JSON and Markdown
evidence. Checks distinguish PASS, FAIL, BLOCKED, NOT_RUN and DEFERRED; manual
checks never become passes without execution.

Target inventory records hashes of operator-declared APK, AAB, IPA and source
archive files as opaque bytes. It does not parse archives, inspect signatures,
install applications or run device tests. Hashing alone leaves tests NOT_RUN.
Backend references are recorded without contacting an endpoint.

Optional local history preserves sanitized run summaries. Retest transitions
require identical target bytes, plan, adapter, implementation and ruleset.
Changed artifacts are incompatible comparisons, not claimed improvements.
History and export checksums are unsigned integrity checks, not authentication,
independent certification or tamper-proof storage.

Windows artifact checks now distinguish same-handle modification detection from
path-versus-handle metadata comparison, avoiding false blocks caused by differing
creation timestamps while retaining modification checks.

Registered source targets contain the supplied source and must remain private.
Reviewer exports omit source, credentials and private paths. No external tool,
repository test suite, device or target application is launched by this release.
Execution adapters remain a separate development phase.

Upgrade and rollback instructions are in [UPGRADES.md](UPGRADES.md). The candidate
extends the tested endpoint window to 0.60.0 and 0.66.0, with direct and sequential
installed-wheel rehearsals. Release verification is complete only after CI and
fresh published-artifact checks finish.
