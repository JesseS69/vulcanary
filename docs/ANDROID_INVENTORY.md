# Read-only Android metadata inventory

This opt-in adapter reads one explicitly selected device and package through an
**already-running, operator-trusted local ADB server**. It is separate from normal
repository scanning and does not close any application security-test requirement.

```text
python -m vulcanary.android_inventory --serial OPERATOR_SELECTED_SERIAL --package org.example.app --user 0 --authorize-read-only-inventory --trust-existing-local-adb-server --output new-private-inventory
```

Choose the device, application and Android user/profile deliberately. User 0 is
the explicit default, not detection of the foreground user. The adapter does not
enumerate devices or select the only connected phone automatically. Its restricted
serial syntax excludes network-address selectors, but is not proof of USB transport
or physical hardware identity. A device name alone must first be resolved in a
separately authorized discovery step. Keep output private until reviewed.

## Connection and execution boundary

There is no `adb` executable invocation, PATH lookup, binary download or server
start/restart/stop. Instead, the adapter sends ADB smart-socket requests directly
to literal IPv4 `127.0.0.1` (default port 5037, configurable). Consequently an
executable pin is neither required nor presented as authentication of the running
server. **The server is a separate trusted component.** This protocol does not
authenticate that server or the device; a malicious local service can fabricate
responses. Do not use an untrusted or forwarded endpoint.

One connection selects `host:transport:<exact-serial>` then requests one
`shell,v2,raw:` session on that same transport. There is no reconnect, fallback
device, pairing, TCP/IP device connection, forwarding or sync request. Fixed
commands read Android release/API/model using `/system/bin/getprop`, and the
selected package's version code and APK paths using `/system/bin/pm`. Commands
contain only validated identifier/integer arguments and generated hex delimiters.
No arbitrary command, source-supplied suite or shell fragment is accepted.

This **does execute OS metadata utilities on the device**, but never launches the
application. Read-only does not prohibit incidental OS auditing or system activity.
No APK bytes, app storage, logs, screenshots, clipboard, accounts, keys or signing
material are read. No install/uninstall, force-stop, permissions, settings, data
clearing or backup/restore action is sent. A shared server may already have other
connections; the adapter does not control that server's independent behavior.

The connection has a total monotonic deadline (10 seconds by default, at most 30),
256 KiB output cap, 64 KiB frame cap, 1,024 frame limit and 128 APK-path limit.
Missing server, transport refusal, malformed/partial frames, stderr, nonzero or
missing exit status, trailing data and timeout all block. There is no legacy-shell
fallback. Closing the socket is not proof that a remote OS utility has terminated.

## Evidence and state

The two package metadata observations must agree, including the path set. Only
one exact package row is accepted; duplicate exact matches or unsupported OEM
formatting block. Android's substring filter can also return similarly named
packages: structurally valid nonmatching rows are discarded, never substituted or
exported. This detects some concurrent changes, not an atomic snapshot or
a change-and-revert between observations. No raw response is retained on failure.

| Inventory outcome | `collection_state` | Security-test `state` | Exit |
|---|---|---|---|
| Metadata collected and structurally validated | COMPLETE | NOT_RUN | 2 |
| Unauthorized, unavailable, incomplete or unsupported | BLOCKED | BLOCKED | 2 |

Completion is not an assertion that the expected candidate is installed. Reports
include a numeric version code, Android release/API, path count and SHA-256 values
for the serial selector, application ID, model and APK paths. They contain no raw
serial, package identifier, model, APK path, stdout/stderr or exception text.
Hashes of guessable values are not secrecy or authentication. New output directories
contain JSON, a concise reviewer summary and unsigned checksums; missing checksums
mean an incomplete export.

Version name, APK bytes, signing, AAB-to-APK lineage, installed split completeness,
runtime behavior and security remain unverified. Matching the build number to an
independent record is useful context, not proof of artifact identity. Copying code
files or running lifecycle tests requires a separate authorized scope.

## Validation

Owned loopback fake-server tests exercise real framing, fragmentation, exact service
transcripts, refusal before connection, malformed streams, output/frame limits,
timeouts, changed metadata and sanitized exports. These are adapter tests, **not
physical-device evidence**. Unsupported responses must remain BLOCKED until a
documented parser change and negative controls are reviewed.

Protocol references: [ADB services](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android15-s1-release/SERVICES.TXT)
and [shell protocol channel definitions](https://android.googlesource.com/platform/system/core/+/refs/heads/android10-gsi/adb/shell_protocol.h).
