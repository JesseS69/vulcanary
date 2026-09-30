# Upgrade support and rollback

For the 0.66 candidate, the declared pre-v1 upgrade test window is **0.60.0 through
0.65.0**. Mandatory installed-wheel fixtures cover the oldest endpoint (0.60.0),
the immediately previous release (0.65.0), and the sequential path through both.
This is not exhaustive execution of every intermediate release or every possible
hand-edited state. Releases before 0.60.0 are outside this tested window; back up
and rehearse against copies before adopting a candidate. Future releases must move
the previous-release fixture forward and explicitly retain or change the oldest
supported endpoint. Never imply compatibility solely from a version comparison.

## Before an upgrade

1. Stop all dashboards and monitors, including one-off processes. Older releases
   do not participate in the new writer locks.
2. Privately back up the complete `.vulcanary` directory and any repository-owned
   suppression/config files. The config-export command deliberately omits the token
   and does not substitute for this full backup.
3. Obtain an immutable release wheel and verify its SHA-256 against the published
   manifest through a trusted channel. Checksums are integrity checks, not an
   independent signature if both downloads come from a compromised publisher.
4. Install the verified wheel, restart, check version, configured repositories,
   history diagnostics and monitoring state, then rescan. Never interpret a pending
   or failed repository as newly clean.

## Rehearsal and evidence

`scripts/rehearse_upgrade.py --old OLD.whl --candidate CANDIDATE.whl` creates a
disposable virtual environment and synthetic home, installs each actual wheel with
`--no-index --no-deps`, seeds real scan state and a sealed receipt, upgrades, checks
state, and reinstalls the old package. `--intermediate PREVIOUS.whl` adds a sequential
forward/backward path. Published inputs are hard-pinned by SHA-256; the candidate is
the local build under review. Only supply trusted wheels: installation executes
Vulcanary's own package, not a scanned repository's code. No downloads occur in this
script. CI explicitly acquires the two pinned release fixtures before running it
on Windows, Linux and macOS.

Checks include config bytes across installation, token/config values across rewriting,
repository suppression bytes, finding fingerprints,
first-seen history, retained collections, rotation acknowledgements and receipt seal
validity after loading and rewriting state. This is fixture-level migration evidence,
not proof for corrupt state, interrupted package installation, or arbitrarily old
releases. New retention counters may be discarded if an older package writes history;
they are diagnostic metadata, not a change to clocks, acknowledgements or seals.

## Roll back a bad release

Stop every process before replacing the package. Back up current state separately,
then install the previous verified immutable wheel. The rehearsal demonstrates
read/write compatibility for the declared fixtures. If real state cannot be loaded,
restore the pre-upgrade backup only after preserving the newer copy; this intentionally
loses changes since that backup. Report that loss, never synthesize resolution proofs.

Maintainers should mark the bad release's notes as withdrawn/not recommended, link
to the known-good release and describe affected users and recovery steps. Do not
replace assets, retag, force-push a release tag or reuse its version number. Publish
a new patch version when repaired. Checksum manifests keep their original meaning.
The rehearsal does not publish an advisory or mutate any GitHub release.
