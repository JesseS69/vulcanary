# Bounded AAB declaration inspection

```text
python -m vulcanary.aab_inspection --aab candidate.aab --backup-requirements requirements.json --output new-review-directory
```

This offline adapter reads a single base module's AAPT2 protobuf manifest and
direct backup XML resource links. It hashes stable local artifact bytes and
emits `vulcanary.aab-manifest-inspection.v1`, separately from the APK report.
It does not run bundletool, Java, Gradle, app code or a device, convert the bundle,
extract archive members to disk, or contact an endpoint. It remains outside
normal scans, gates, SLA tracking and dashboard history.

Requirements, exact/whole-domain matching, conditional suffix handling and
sanitized exports follow [APK inspection](APK_INSPECTION.md). `debuggable` and
`allowBackup` use compiled booleans or documented Android defaults when absent;
unresolved boolean references do not become defaults. PASS means a declaration
check passed, FAIL means that declaration assertion failed, and BLOCKED means
the evidence is insufficient. Runtime backup effectiveness always remains
BLOCKED, so the aggregate currently always exits **2**, even when individual
assertions pass. JSON, CLI and Markdown retain separate assertion counts.

## Supported boundary

- Only `base/manifest/AndroidManifest.xml`, with no feature/other modules or root
  APK manifest. `BundleConfig.pb` must be present but its contents are not interpreted.
- `base/resources.pb` links must resolve by numeric ID to a direct PROTO_XML file
  in `base/res/`, with a single default configuration. Names/raw spellings never
  substitute for a missing compiled resource ID.
- Duplicate singular protobuf fields, conflicting oneofs, malformed wire data,
  unknown fields in inspected messages, unsupported XML grammar and duplicate
  resource IDs are refused. Aliases, overlays, staged/flagged selected entries,
  dynamic references and configuration selection are not inferred.
- Unrelated resource values and source-position metadata are opaque. This is
  not a general protobuf, bundle, signature or installability validator.
- The artifact hash is recorded only after supported manifest processing and
  unchanged-handle/path checks. An unresolved backup resource can retain an
  artifact identity and valid manifest checks while its assertions stay BLOCKED.
  Archive read warnings invalidate all checks and the artifact identity.

The decoder follows [AOSP Resources.proto](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/tools/aapt2/Resources.proto).
Tests include a separately Android-SDK-compiled fixture with pinned hashes,
adversarial wire/XML/resource cases, limits, seeded mutations and source-free
export checks. The SDK is only used to prepare the committed test fixture, never
by the adapter or CI tests.

## Limits and evidence

Existing archive safeguards apply: 512 MiB artifact, 10,000 entries, 4 MiB central
directory, 1 MiB per manifest/rule, 8 MiB resource table, no ZIP64, duplicates,
encrypted members or symlink payloads. Across a read, protobuf interpretation
allows at most 500,000 fields and 4 MiB decoded text. Each XML document permits
8,192 elements, depth 64 and 256 attributes per element. These limits are emitted
in the report. Unsupported or over-limit data yields BLOCKED evidence, not PASS.

Reports expose generated IDs, fixed reasons, booleans, counts and hashes, not
package names, private paths, raw XML, exception text or resource strings.
Checksums are unsigned integrity evidence. Neither a source commit match nor
an artifact hash proves a reproducible build, installed version, device behavior,
successful backup/restore or independent certification.
