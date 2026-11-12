# Offline APK manifest declaration inspection

This experimental adapter reads the compiled AndroidManifest.xml inside an
explicitly supplied APK. It hashes the same open artifact handle, checks that it
remained stable, and reports selected boolean declarations and backup-file hashes. Nothing is
extracted, installed, executed, uploaded or read from a device.

```text
python -m vulcanary.apk_inspection --apk candidate.apk --output new-apk-review
```

The output directory must be new. It contains report.json, reviewer.md and unsigned
checksums.json. Artifact and implementation hashes identify the inspected bytes;
they do not authenticate the author, signatures, installability or installed build.
Package names, source paths, raw strings and resource identifiers are not exported.

## Checks and limits of the result

| Check | Expected declaration | Interpretation |
|---|---|---|
| debuggable | false | Typed false or the documented absent-attribute default passes this declaration check; true fails it |
| allowBackup | false | Typed false passes this declaration check; true or the documented absent-attribute default fails it |
| backup-exclusions | verified rules | Always BLOCKED: locating a referenced file does not evaluate its exclusion rules or custom backup behavior |

The false expectation is this adapter's release/privacy assertion, not a universal
Android policy. An app may deliberately permit backup. Resource references and
unsupported value types are unresolved, never assumed false. Names, Android
namespaces and framework attribute IDs must agree; ambiguous encodings are blocked.
Raw and typed boolean values must agree when both are present.

### Backup resource links are evidence, not passing checks

`backup_resources` records `fullBackupContent` and `dataExtractionRules` separately.
Typed references are followed through a bounded `resources.arsc` table only when a
default entry exists and every supplied configuration for that entry names the same
direct XML member. The member's bytes are hashed without exporting its path or
contents. This does not validate XML contents, exclusions, device-selected behavior,
or the protection of any particular key. Even arbitrary non-XML member bytes can
be hashed; that is deliberately not a policy verdict.

Resolution states are `not_declared`, `literal_true`, `literal_false`,
`resolved_file`, and `unresolved`. Literal values are declarations, not verified
backup outcomes. Missing files/tables, aliases, divergent configurations, absent
defaults, sparse/compact entries, overlays and unsupported layouts remain
`unresolved`. A partial link result never clears the backup-exclusions BLOCKED row.
Framework resource IDs, rather than raw display strings, select referenced entries.

The overall report is BLOCKED and execution exits 2 because backup-rule coverage
is incomplete, even when both boolean checks pass. Individual FAIL rows remain
visible alongside the gap. No result claims that a device cannot back up data,
that exclusion rules protect private keys, or that a release is safe to install.
Device/OS behavior still needs separate testing, especially device-to-device
transfer behavior on newer Android releases.

The parser handles a bounded subset of binary XML with UTF-8/UTF-16 string pools,
namespace nodes, resource maps, start/end elements and typed booleans. A missing
application element, duplicate relevant attributes, mismatched framework IDs,
broken trees, invalid Unicode and unsupported chunks remain BLOCKED. Text XML,
AAB/protobuf, split-set merging and ZIP64 are outside this slice.

Bounds: 512 MiB APK, 4 MiB central directory, 10,000 actual archive entries, 1 MiB
compressed/uncompressed manifest, 8,192 strings/chunks, 4 KiB per encoded string,
1 MiB aggregate decoded string bytes, 256 attributes per element and depth 64.
The central directory is counted before ZipFile object allocation. In addition to
the manifest, only a referenced resource table (8 MiB compressed/uncompressed) and
at most two linked files (1 MiB each compressed/uncompressed) may be decompressed.
Resource tables are limited to 32 packages, 8,192 chunks per container, 65,536 entry
offsets per type and 65,536 strings per pool. The per-string and aggregate decoded
byte caps remain 4 KiB and 1 MiB respectively; the manifest retains its 8,192-string
limit. Declared configuration counts are checked against actual type chunks.
Oversize and malformed inputs require a supported,
bounded artifact or a separate trusted inspection workflow; they are not clean.
Encrypted or symlink members are refused; duplicate archive names block inspection.
UserWarning raised while opening or reading any inspected member (including overlap
warnings on Python versions that warn instead of raising) also blocks inspection;
warning text and member names are not echoed to stderr or exports.

Aggregate state is derived from the check results, with incomplete coverage taking
precedence over failure. Empty or unsupported state sets cannot pass. Since backup
exclusions remain unresolved, all current real inspections still exit 2.

## Format references and external validation

The layout follows the [AOSP binary resource definitions](https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168/libs/androidfw/include/androidfw/ResourceTypes.h).
Boolean meanings/defaults come from the [Android application element reference](https://developer.android.com/guide/topics/manifest/application-element);
framework IDs are listed in [android.R.attr](https://developer.android.com/reference/android/R.attr).

Two compiled fixtures were downloaded from AOSP commit
`1cdfff555f4a21f71ccc978290e2e212e2f8b168` for read-only validation:

| Path under libs/androidfw/tests/data | SHA-256 | Observed result |
|---|---|---|
| basic/basic.apk | e9947602b195f741150d38884cf3e2f7c2fefea7191c838e26d812f8f65c3d1b | debuggable default false; allowBackup default true; exclusions unresolved |
| app/app.apk | 2af38a06a1ab7c0af164abbd5599db738a220df3b6546abae08e5a1a883fedad | no application element; all checks BLOCKED |

The paired upstream source manifests agree with these observations. These tiny
resource-test APKs are not evidence of compatibility with all production APKs.
They were neither executed nor installed, and no upstream build scripts were run.
They are not bundled or automatically downloaded by Vulcanary or its test suite.
To reproduce, retrieve the files from the pinned source tree, verify these hashes,
and invoke the command above. Synthetic binary fixtures in the permanent suite
cover explicit booleans, resource references, UTF encodings and negative cases;
200 seeded binary-manifest mutations and 300 archive mutations exercise
malformed-input handling without network access. Archive operators include bit
changes, truncation, insertion, deletion, duplication and bounded 50 KiB inflation.
An additional 2,000-trial out-of-band run against the pinned basic.apk fixture
completed without crashes. These measurements do not prove every malformed input
is handled, nor that mutations outside the manifest must make declarations unreadable.

The resource-link tests add 10,000 deterministic table mutations (bit changes,
truncation, insertion, deletion, duplication, null-byte inflation, extreme integers
and malformed Unicode), same/different
configuration pairs, alias/default/specification/bounds refusals, missing and
oversize linked members, warning redaction and complete APK-to-report checks.
The two AOSP APKs above validate the manifest path, not backup-resource links.
A locally supplied release APK additionally exercised a real compiled table with
18,230 global strings and nonzero declared configuration counts: both backup
references resolved to hashed members (428 and 788 bytes). This is a local
compatibility observation, not an independently reproducible public corpus; the
artifact and its paths are not distributed. Broad external backup-resource corpus
validation remains outstanding. Rule contents and platform behavior remain a
separate step.
