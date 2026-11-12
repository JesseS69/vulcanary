# Verifying release provenance

## Status and policy

Releases through **v0.68.0 do not have distribution attestations**. Their checksum
manifests cover four payload files but are not signatures. Existing scan-report
attestations from `vulcanary.yml` do not attest release distributions.

The release gate requires GitHub keyless SLSA provenance for every future
distribution asset before publication: wheel, source archive, installer, uninstaller
and the checksum manifest itself. The manifest still contains only four hashes;
it cannot hash itself. Attestations are stored by GitHub, not added as a sixth
downloadable asset. No existing tag or artifact is rewritten.

The readiness criterion is **Met** following the v0.69.0 live gate and independent
artifact verification. Unit tests and a workflow diff alone were insufficient.

### Recorded live evidence

- Release: [v0.69.0](https://github.com/JesseS69/vulcanary/releases/tag/v0.69.0),
  commit `ac67e069aa2edf8bf24b46a2a1f2f677e2a5f926`.
- [Tagged workflow 43113831512](https://github.com/JesseS69/vulcanary/actions/runs/43113831512)
  completed build, Windows lifecycle, attestation/verification and publication.
  Publication depended on successful provenance verification.
- Independent review downloaded all five assets into an empty directory and ran
  the verifier from a trusted main checkout, using the commit from the tag ref
  rather than the downloaded artifacts. Expected identity verified with exit 0.
- The independent negative control changed the final commit digit to `7`.
  Verification rejected the mismatched BuildSignerDigest and returned exit 2.

This records the independent review evidence supplied after release; it is not
a new certification or a claim about earlier releases. Every subsequent release
must still pass its own gate. No provenance check proves source-code safety,
reproducibility, dependency integrity, or application security.

## Consumer procedure

Use a trusted installation of GitHub CLI supporting `gh attestation verify`, plus
Python 3.11+. Neither is installed automatically. Authenticate GitHub CLI if required.
Obtain the expected full commit and release tag from the reviewed release record;
do not take identity solely from an artifact or an arbitrary supplied attestation.
Use a trusted copy of `scripts/verify_release.py`, not a script extracted from the
unverified archive you are checking.

1. Download all five assets into a new otherwise empty directory. Do not run the
   installer or install the wheel yet.
2. Run the verifier, substituting the actual tag and independently expected 40-character
   commit (the following is a template, not a claim that v0.68.0 verifies):

   ```text
   gh release download vX.Y.Z --repo JesseS69/vulcanary --dir downloaded-release
   python scripts/verify_release.py --directory downloaded-release --tag vX.Y.Z --commit EXPECTED_FULL_COMMIT
   ```

3. Proceed only when the command exits zero and confirms all five assets. Retain
   the tag, commit, workflow-run URL, verification output and date with your evidence.
   If it fails, do not install: inspect missing assets, checksum mismatch, expected
   identity, CLI support/authentication and network availability. Do not remove the
   identity constraints to get a passing result.

The helper checks exact asset names, manifest completeness and hashes, then asks
GitHub CLI to verify each asset against this policy:

- Repository `JesseS69/vulcanary` and signer `.github/workflows/release.yml`.
- Exact certificate identity for that workflow at the expected tag.
- Expected tag ref, source commit and signer commit.
- SLSA provenance v1 predicate and GitHub-hosted runner.

No downloaded file is installed or executed. The helper runs the already trusted
`gh` command from PATH and contacts GitHub/Sigstore verification services; it is a
release-maintenance utility, never part of an offline repository scan. Missing
attestations, unavailable services, CLI errors and timeouts fail closed. This helper
does not support offline bundle verification. For that separate workflow, use the
official CLI instructions and preserve trusted-root material and the same identity
constraints; do not treat an unverified JSON bundle as proof.

## What this establishes

Successful verification connects the bytes to the expected workflow identity and
source revision under GitHub's signing infrastructure. It is not proof that source
code is safe, dependencies are trustworthy, builds are reproducible or an independent
security review occurred. Compromised repository/workflow authority remains a risk.
The signing job attests the build artifacts downloaded within the same workflow run;
it is not a separate independently trusted builder.

The dedicated tag-only signing job has OIDC and attestation permissions. PR builds
and ordinary scans do not receive those new permissions. Publication depends on
both platform lifecycle tests and successful provenance verification. A signing or
verification failure leaves the tag/build available for investigation without
publishing an unverified release. Fixes use a new reviewed commit/version rather
than overwriting a published artifact.

References: [GitHub attestation action](https://github.com/actions/attest) and
[GitHub CLI verification policy flags](https://cli.github.com/manual/gh_attestation_verify).
