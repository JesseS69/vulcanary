# Installed APK code-file collection

This separate opt-in adapter copies approved package code files. Inventory
authorization alone does not authorize copying: obtain explicit permission for
the device, package, profile and private output destination.

```text
python -m vulcanary.android_apk_collection --serial SELECTED_SERIAL --package org.example.app --user 0 --inventory approved-inventory/report.json --authorize-apk-code-copy --trust-existing-local-adb-server --output new-private-apks
```

The approved [inventory](ANDROID_INVENTORY.md) must be COMPLETE for that selector,
package and user. All its observations must match a fresh query before transfer.
It is unsigned operator scope, not proof of ownership or AAB generation provenance.

## Read boundary

One selected sync connection remains open across the metadata queries. Each query
selects the same serial, without retry or fallback. Only `LST2` (component lstat)
and `RECV` (read) sync requests are supported. No executable, daemon, pairing,
server lifecycle, arbitrary path, listing, device write or app launch is offered.

Fresh paths must match approved path digests. This subset supports `/data/app/`
installations in one package-prefixed directory, exactly one `base.apk` and optional
`split_*.apk` files. Other layouts block. Traversal, unrelated packages, unexpected
names, observed symlinks and non-regular files refuse before reading their bytes.
Every ancestor below `/` is checked without enumerating directory contents.

The server and device remain trusted. `lstat` followed by `RECV` is **not an atomic
no-follow open**: a hostile device can race lookup or fabricate responses. Device,
inode, mode, size, mtime and ctime comparisons plus metadata snapshots detect some
changes, not every mutation. Access time is excluded because reading may change it.
These controls are not authentication, a sandbox or an atomic device snapshot.

## Bounds and incomplete results

- Maximum 32 files, 256 MiB per file and 512 MiB aggregate, checked before transfer.
- Total deadline: 120 seconds by default, maximum 300; metadata queries share it
  and retain their own maximum 30-second limit.
- Maximum 64 KiB per data frame and 131,072 frames per file. Extremely fragmented
  streams can exhaust the frame budget below the byte cap.
- Exact declared byte count and DONE required. Errors, truncation, extra data,
  unsupported replies, timeouts or changed metadata block the entire set.

Generated local names use `.partial` until the full set is consistent and local
bytes have been rehashed. Exclusive hard-link promotion avoids replacing an existing
destination; filesystems without hard-link support block. Use a trusted private
output directory, not one a hostile local process can replace during the run.

Failure attempts to remove only files this run created; `cleanup_complete` exposes
refusal. A crash or export failure can leave incomplete files. Completeness requires
a COMPLETE report and matching checksums for every artifact, never just `.apk`
filenames. Existing directories are not reused or recursively deleted.

`vulcanary.android-apk-collection.v1` has security state NOT_RUN or BLOCKED, never
PASS; exit is always 2. Reports contain generated artifact IDs, base/split roles,
sizes, byte hashes and device-path hashes, not raw paths, selectors, application IDs
or exceptions. **The APK copies themselves can contain proprietary code and packaged
configuration.** Keep them private; do not publish the evidence directory. Checksums
are unsigned integrity records. Socket closure does not prove remote work terminated.

## Offline follow-up

Run [APK inspection](APK_INSPECTION.md) on the complete base copy using independently
derived requirements, and verify its digest matches collection. The parser does not
merge split manifests. Signing, split completeness, AAB lineage, backup effectiveness
and runtime security remain unverified. New hashes copied into an expected record
are not independent candidate verification. Build-number agreement is limited metadata
evidence, not build provenance.

The separately authorized [offline signature adapter](APK_SIGNATURES.md) can check
copied APK signatures using a pinned trusted SDK tool. It does not turn collected
hashes into independent release expectations or prove AAB lineage.

The adapter stays outside normal scanning, gates, SLA and dashboard history.
Fake-server tests demonstrate transport/refusal behavior, not application security.

References: [AOSP wire layout](https://android.googlesource.com/platform/system/core/+/67d52aa0f684fe6fb898c2ccda1d7bb302d3a5e0/adb/file_sync_protocol.h)
and [AOSP ordinary read-only open](https://android.googlesource.com/platform/system/adb/+/ade16721cd500176fe2d0040fa3a61f75dac8801/file_sync_service.cpp).
