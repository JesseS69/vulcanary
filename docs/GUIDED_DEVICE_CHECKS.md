# Guided device check preparation

This experimental offline adapter prepares instructions for an existing registered
Android or iOS candidate. It performs **no tests**, gathers no observations and
cannot produce PASS. It is not a device runner or a manual attestation editor.

```text
python -m vulcanary.guided_device_checks --manifest PRIVATE_MANIFEST.json --output NEW_DIRECTORY
```

The manifest is the existing `vulcanary.candidate-manifest.v1` contract described in
[Candidate testing](CANDIDATE_TESTING.md). Preparation does not authorize execution:
device actions, accounts, settings changes and screenshots still need their own
approved scope. Read-only metadata inspection approval does not authorize following
these instructions on a phone. Use only isolated synthetic fixtures.

| Requested requirement | Instructions |
|---|---|
| privacy-app-switcher | Private synthetic screen previews |
| password-controls | Masking/visibility and mismatch feedback |
| keyboard-text-sizing | Keyboard open/closed and ordinary/largest text sizing |
| first-use-discoverability | Uncoached synthetic journey |

Other requested requirements are listed as `unsupported_requirements`, never
silently treated as covered. This subset does not implement protected-screen capture
prevention, permission flows, native lifecycle faults, storage rollback, screenshots
or accessibility automation.

`report.json` and `checklist.md` contain NOT_RUN rows, null observations, empty
evidence and `executed: false`. Missing identity fields are listed. There is no input
for free-form notes, secrets, screenshots or success attestations. Hashes bind the
private candidate and manifest; version strings, account identifiers and paths are
not copied into the export. This is not verification of the installed candidate.
Human observation cannot substitute for required installed-device evidence.

The command returns **2 even when preparation succeeds**, because no check ran.
Refusal prints a fixed BLOCKED message without input paths or exception details.
An empty selected checklist stays NOT_RUN. Existing output directories are refused.
An interrupted export can leave a partial directory; missing `checksums.json` means
incomplete export. Use a new output directory. Checksums are unsigned integrity
checks, not authentication or certification.

The separate experimental schema is `vulcanary.guided-device-checklist.v1`.
Editing a checklist is not evidence ingestion, and no scan policy, SLA, ledger,
dashboard or candidate result is updated. This preparation has no retest verdicts.
