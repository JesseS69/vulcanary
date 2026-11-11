# v0.69.0 release notes

This release introduces a provenance gate for published distributions. After the
build and Windows lifecycle checks, a dedicated tag-only job creates GitHub keyless
attestations for the wheel, source archive, installer, uninstaller and checksum
manifest. Publication requires successful verification of all five assets against
the expected repository, workflow certificate identity, tag and commit.

The checksum manifest still lists four payload hashes; it cannot hash itself.
Its identity is covered by the attestation instead. Attestations are stored by
GitHub; the release retains five downloadable assets. Releases through v0.68.0
remain checksum-only distributions and are not retroactively attested.

Consumers can use the trusted `scripts/verify_release.py` helper and the
[provenance guide](RELEASE_PROVENANCE.md) to verify downloaded files before
installation. Missing evidence, mismatched identity, unavailable verification
services or unsupported tooling fail closed. Use an independently expected tag and
full commit and a trusted GitHub CLI installation; the helper runs `gh` from PATH.

Provenance connects artifact bytes to the expected workflow and source revision.
It does not prove source safety, reproducibility, dependency integrity or independent
security certification. Ordinary scans, reports, gates, SLA behavior and the trusted
local-test adapter are unchanged.

The declared upgrade endpoint window advances to 0.60.0 and 0.68.0. See
[upgrade and rollback procedures](UPGRADES.md). Provenance readiness remains Open
in this candidate: the first tagged signing run and freshly downloaded artifact
verification must succeed before the criterion can be marked Met. If verification
blocks publication, investigate the tagged workflow rather than bypassing its gate.
