# Offline APK signature verification

For API 37 hybrid signatures, use the separately scoped
[SDK 37 hybrid profile](APK_HYBRID_SIGNATURES.md). This classical profile is unchanged.

This opt-in adapter runs an installed Android SDK `apksigner.jar` through an
explicit, hash-pinned Java executable. It never installs an app, contacts a device,
downloads a tool or accesses signing keys. The APK is input data to a trusted tool;
its application code is not launched. Normal scans/gates/SLA remain unchanged.

```text
python -m vulcanary.apk_signatures --artifact /absolute/copied.apk --artifact-sha256 APPROVED_BYTES_SHA256 --java /absolute/java --java-sha256 JAVA_SHA256 --jar /absolute/apksigner.jar --jar-sha256 JAR_SHA256 --android-api 36 --expected-cert-sha256 INDEPENDENT_CERT_SHA256 --authorize-trusted-verifier --output new-signature-report
```

All three input paths must be absolute regular files, not symlinks. Bare executable
names, PATH resolution, batch wrappers and caller-supplied command fragments are
not supported. Tool pins are operator trust inputs, not distribution authentication.
The Java installation and its libraries must be trusted: hashing the launcher does
not authenticate its DLLs/libraries or make executable launch an atomic operation.

The artifact digest approves exact input bytes; a collected APK digest is not an
independent release expectation. Source files are bounded and checked for changes;
JAR/APK snapshots use generated names in a fresh temporary directory. Hashes are
checked again after execution. The inherited environment is replaced, removing
Java option/classpath injection. No unrestricted stdout, stderr or exceptions are
exported. The temporary directory must be removed before any PASS can survive.

## What the checks mean

| Check | PASS | FAIL or BLOCKED |
|---|---|---|
| signature | SDK verifier accepts the exact APK for the selected API | Explicit rejection is FAIL; crashes, timeouts and unsupported output are BLOCKED |
| expected_signer | Current signer certificate SHA-256 matches the supplied expectation | Mismatch is FAIL; missing independent expectation remains BLOCKED |
| warnings | No warnings reported | Any warning count is BLOCKED pending review, not silently discarded or called an invalid signature |

BLOCKED takes precedence over FAIL overall; per-check failures remain visible.
Exit is 0 for all-checks PASS, 1 for overall FAIL, 2 for BLOCKED/refusal. **PASS is
only these scoped checks, not application security or independent certification.**

Expected certificate SHA-256 must come from a separately trusted release-certificate
record, encoded as 64 lowercase hexadecimal characters without colons. Such a
record can be an operator-verified app-signing certificate record. A repository's
app-links declaration is a useful comparison but is not automatically a trusted
Play signing identity. Do not substitute the upload certificate for the app-signing
certificate. Copying the just-observed fingerprint into expectations is circular.
The tool cannot prove the provenance of operator-supplied expectations.

Only one current signer and the known `apksigner` 0.9 output structure are supported.
The supplied tool version is checked before verification. Unknown output, ambiguous
signers and malformed responses block. Source-stamp certificate output is never
substituted for the application's signer. Source stamps, certificate ownership,
revocation, rotation history, AAB generation lineage and split completeness are not
verified by this adapter. Matching signers across splits is useful context, not
proof of a complete set or matching release source.

Verification specifies both minimum and maximum SDK as the selected API (supported
range 24–36). It does not claim verification across every supported Android release.
The standard `verify --verbose --print-certs` operation is used; warnings are counted
separately instead of interpreting a `-Werr` rejection as an invalid signature.

## Execution and evidence limits

APK input: 256 MiB maximum. Java launcher/JAR: 32 MiB each. Output: 16 KiB per
invocation. The worker-time budget defaults to 30 seconds (maximum 120) across
version and verification; local snapshot hashing/export is separately byte-bounded,
not a hard total elapsed deadline. Java heap is capped at 64 MiB with additional
fixed runtime memory settings. Windows uses the existing 256 MiB process Job
limit; POSIX uses a separate process group, not an equivalent OS memory limit.

This is **not an OS network/filesystem sandbox**. A trusted Java verifier runs
with native access for its bundled provider. Forced stops override even a zero
process exit. Existing output directories are never overwritten. JSON/Markdown
reports contain artifact/tool/certificate hashes, scheme booleans, counts and fixed
reasons, not certificate names, member paths, tool paths or raw diagnostics.
Checksums are unsigned; output hashes do not authenticate evidence.

## Repeatable SDK integration controls

`tests/fixtures/apk-signatures/` contains a public synthetic APK signed using a
disposable RSA-2048 key and an independently compiled AAPT2 manifest. No private
key or password is retained. Provenance pins the APK, certificate, manifest and
SDK JAR. These are test identities, never release identities.

```text
python scripts/check_apk_signature_fixture.py --java /absolute/java --java-sha256 JAVA_SHA256 --jar /absolute/apksigner.jar --jar-sha256 JAR_SHA256 --authorize-trusted-verifier
```

This explicit integration check verifies the valid fixture, rejects a wrong expected
signer, and flips one synthetic asset byte to prove signature rejection. It does not
download an SDK. The dependency-free unit suite uses controlled worker responses for
output/refusal/privacy behavior; those mocks are not cryptographic verification.

Reference: [Android SDK apksigner verification](https://developer.android.com/tools/apksigner).
