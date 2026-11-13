# Explicit SDK 37 hybrid signature profile

This opt-in module is separate from the [classical API 24–36 adapter](APK_SIGNATURES.md).
It accepts only API 37 and SDK output describing a v3.2 classical/PQC pair plus a
V3.0 fallback. A successful classical-path check says nothing about the hybrid
signatures. This module requires the verifier to report v3.2 verification itself.

```text
python -m vulcanary.apk_hybrid_signatures --artifact /absolute/copied.apk --artifact-sha256 APPROVED_BYTES_SHA256 --java /absolute/java --java-sha256 JAVA_SHA256 --jar /absolute/sdk37/apksigner.jar --jar-sha256 JAR_SHA256 --android-api 37 --expected-classical-sha256 INDEPENDENT_CLASSICAL_CERT_SHA256 --expected-pqc-sha256 INDEPENDENT_PQC_CERT_SHA256 --authorize-trusted-verifier --output new-hybrid-report
```

The two expected fingerprints are independent operator trust inputs. Obtain each
from its appropriate trusted release certificate record. Never use the older
fallback fingerprint, source-stamp fingerprint, or the just-observed hybrid
fingerprint as a substitute. Public fixture certificate pins below are test
identities, not proof of independent release identity. A missing role remains
BLOCKED; any supplied role mismatch is FAIL even if the other role is missing.
Identical expected fingerprints for the two roles refuse before execution.

## Contract

The schema is `vulcanary.apk-hybrid-signature-verification.v1`, deliberately separate
from the earlier report. `signers` names `classical`, `pqc` and `fallback` explicitly;
only the first two enter `expected_hybrid_signers`. SDK ranges and development-release
annotations are preserved for each hybrid role and must agree and cover API 37.
The source stamp is not promoted to an application identity. Duplicate certificates,
unrecognized roles/lines, inconsistent ranges and absent v3.2 verification block.

The adapter uses the external verifier's accepted cryptographic result. It does not
implement its own cryptography or independently reproduce every platform policy.
It currently refuses other output shapes, including V3.1 fallback configurations,
multiple hybrid ranges and additional roles. The tool's `0.9` version string is not
a capability or distribution identity: the explicit module, JAR pin and strict
output structure all matter. No SDK is automatically downloaded or selected.

Three checks stay separate: signature, both expected hybrid identities, and warnings.
Any warning remains BLOCKED. A known warning ID is not automatically harmless, and
documented meaning is not proof that a particular shipped verifier enforces it.
Overall BLOCKED outranks FAIL; per-check failures remain visible. Exit 0 requires
PASS, 1 means overall FAIL, and 2 means BLOCKED/refusal.

The fixed external invocation, byte/time/output limits, temporary copies, post-run
hash checks, replaced environment and process-tree cleanup follow the classical
adapter. Shared stable-copy code is included in this module's implementation digest.
Cleanup failure clears all certificate/range observations and every PASS.
This is trusted tool execution, **not an OS network/filesystem sandbox**. Hashing
the Java launcher does not authenticate its libraries. Application code is not run,
and normal scans, gates, SLA and dashboard paths remain unchanged. Reports omit raw
diagnostics, certificate names and paths; checksums are unsigned.

## Reproducible public controls

`tests/fixtures/apk-hybrid-signatures` contains three public AOSP synthetic APKs
at pinned commit `083507e4e70f21f3805889e7753874345a43e6fc`, with upstream URLs,
byte hashes and the upstream Apache-2.0 license. No private signing keys are included.
One fixture has a valid hybrid pair; the others intentionally contain two classical
or two PQC signers. The valid fixture uses a development-release SDK annotation;
the parser records that annotation rather than silently discarding it.

```text
python scripts/check_apk_hybrid_fixture.py --java /absolute/java --java-sha256 JAVA_SHA256 --jar /absolute/sdk37/apksigner.jar --jar-sha256 JAR_SHA256 --authorize-trusted-verifier
```

The explicit integration script runs eight controls: real hybrid acceptance,
synthetic role-pin matching, swapped-role rejection, preservation of the fixture's
warning, both invalid-role APKs, and one-byte corruption of each hybrid signature.
It never downloads tools or contacts a device. Its exit 0 means the controls met
their expected outcomes, including the warning BLOCKED outcome; it does not mean
the fixture achieved an overall security PASS. The normal unit suite uses synthetic
worker responses for parser/refusal/privacy cases and does not pretend mocks verify
cryptography. This work does not certify a cryptographic design, establish all
rotation/rollback or stripping protections, prove AAB lineage or validate runtime
behavior. Private application evidence is not included in this repository.

References: [AOSP v3.2 format and verification](https://source.android.com/docs/security/features/apksigning/v3-2),
[pinned AOSP tests](https://android.googlesource.com/platform/tools/apksig/+/083507e4e70f21f3805889e7753874345a43e6fc/src/test/resources/com/android/apksig/).
