# Offline Android candidate identity

```text
python -m vulcanary.android_identity --artifact candidate.aab --expected private-expected.json --output new-identity-review
```

This command checks the exact artifact digest, application identifier, long version
code and version name against a separately supplied candidate record. It reads APK
binary XML or single-base AAB protobuf through the existing bounded readers. It
does not use the filename as evidence, launch tools, execute the app, contact a
service or read a device.

The private expected file has exactly these fields:

```json
{
  "schema": "vulcanary.android-identity-expectations.v1",
  "artifact_format": "aab",
  "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "application_id": "org.example.app",
  "version_code": 31,
  "version_name": "1.0.2"
}
```

The zero digest above is a placeholder, not a working expectation. Get values from
the independent candidate/build record. Copying inspected values into expectations
would only verify a self-consistent file, not the intended candidate. State the
provenance and uncertainty when any expected field comes from current source
configuration rather than a frozen build record. Expected records are unsigned.

The file is limited to 16 KiB, rejects duplicate keys and additional fields, and
requires all four expected identity values. Format is explicit: APK bytes cannot
be inspected by selecting AAB, and vice versa. Version fields must be direct values;
resource references and missing fields remain BLOCKED. An absent versionCodeMajor
means zero; the long code combines major in the upper 32 bits and versionCode in
the lower 32 bits. This subset accepts only nonnegative signed-32-bit components.

## Results and boundaries

`vulcanary.android-artifact-identity.v1` reports four assertions:

| State | Meaning |
|---|---|
| PASS | All four observed values match the supplied expected record |
| FAIL | A completed identity assertion disagrees with its expectation |
| BLOCKED | Parsing or a required identity value could not be established |

BLOCKED takes precedence over FAIL; individual failures remain visible. Exit codes
are 0 for PASS, 1 for FAIL and 2 for BLOCKED/refusal. A modified artifact with the
same package/version fails the digest assertion. Missing metadata is not defaulted
into a pass. A checked artifact hash identifies bytes; it does not authenticate them.

Application identifier and version name are emitted only as SHA-256 of their UTF-8
values. Version code is numeric. Reports include the expected-record digest,
implementation digest, bounds, sanitized assertions and explicit unverified areas.
No filenames, raw package/version strings or exception text are exported. Hashing
guessable values is not encryption or a guarantee of secrecy. Output directories
must be new; export checksums are unsigned integrity checks.

**Identity PASS is not a security PASS or an installed-version claim.** It cannot
prove an APK was generated from an AAB, even if their package/version fields match.
It does not validate signing, generation lineage, split-set completeness, device
OS, account, environment, behavior or backup effectiveness. An AAB is input to
device-specific APK generation; inspecting it is not inspecting the generated
APK or a phone. Reports explicitly retain those unverified areas and remain
outside normal scanner gates, SLA and dashboard history.

See [APK declarations](APK_INSPECTION.md) and [AAB declarations](AAB_INSPECTION.md)
for format limits. Shared readers use stable-handle/path checks, bounded archives
and fail-closed warning handling. Synthetic manifests compiled independently with
Android SDK AAPT2 are pinned for both formats, with wrong-value and altered-byte
controls, malformed inputs, mutation coverage and source-free export tests.

Platform references: [Android versioning](https://developer.android.com/studio/publish/versioning)
and [AOSP attribute IDs](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/res/res/values/public-final.xml).
