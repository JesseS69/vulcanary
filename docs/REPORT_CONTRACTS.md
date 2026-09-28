# Report compatibility contracts

These contracts freeze the emitted wire formats, not detection results. New rules,
advisories, or improved analysis can change findings without a format-version bump.
Existing findings must retain their identity unless an explicit migration is supplied.

## Version boundaries

| Surface | Version selector | Evidence |
|---|---|---|
| Normalized JSON | `version: 1` | Local JSON Schema and golden report |
| SARIF | `version: "2.1.0"` | Pinned OASIS schema and golden report |
| CycloneDX | `specVersion: "1.5"` | Pinned CycloneDX schema, SPDX license and JSF references, golden report |
| SPDX | `spdxVersion: "SPDX-2.3"` | Pinned SPDX schema and golden report |
| OpenVEX | `@context: "https://openvex.dev/ns/v0.2.0"` | Pinned OpenVEX schema and golden report |
| Ruleset manifest | `version: 1` | Local schema, full golden rules and digest |
| Remediation receipt | Legacy v1, selected by the documented field set, **no embedded version** | Local schema, golden proof and seal/tampering tests |
| Experimental dataflow | `schema: "vulcanary.experimental-dataflow.v1"` | Separate local schema and golden exposure fingerprint |

CycloneDX `version` and OpenVEX `version` are document revisions, not schema versions.
The tool release version is provenance, not a format selector. Receipts are not
retroactively given a version field: changing the sealed payload would invalidate
existing proofs. A future incompatible receipt must use a separately identifiable
envelope and retain the legacy verifier or provide an explicit migration.

## Additive versus breaking

- A new **optional** field is additive only where the selected schema permits it.
  Consumers of Vulcanary-owned formats should ignore unknown optional fields.
  Arbitrary properties are not valid extensions to closed upstream schemas.
- Removed or renamed fields, changed types/meaning, new required fields, and new
  enum values are breaking changes. Exhaustive consumers cannot safely assume a
  new enum value is additive. Use a new format version, migration notes, and fixtures
  for old and new consumers rather than silently updating the golden file.
- `metadata`, `policy`, and exception/check diagnostic records contain extensible
  producer-specific payloads. The local schemas constrain their container types;
  they do not promise every internal diagnostic key as a stable public field.
- Finding fingerprints are stable identity, not incidental formatting. Golden
  normalized JSON, SARIF partial fingerprints, selected receipt fingerprints, and
  experimental sink fingerprints are literal committed values. Do not regenerate
  them to make a failing test pass without explaining the identity change.
- Ruleset content/digest legitimately changes when detection changes. Review the
  complete golden diff; do not claim that schema validation alone proves behavior
  or fingerprint continuity across arbitrary inputs.

Experimental dataflow is an independent research contract. It remains outside
findings, gates, SLA clocks, receipts, and remediation. Its detection coverage and
gap taxonomy may evolve independently of stable formats, but incompatible report
shape changes still require a new experimental schema identifier. Research-schema
changes neither bump nor silently redefine normalized JSON v1.

## Reproducing the checks

The normal dependency-free suite checks exact production-exporter output against
`tests/contracts/golden/`. It fixes only clocks, UUIDs, and producer release strings
at their sources; fingerprints, ruleset digest, receipt proof, fields, and arrays
are not normalized away. Fixtures include all six severities, direct/transitive
inventory, an affected advisory, and an experimental source-to-sink exposure.

In a development environment with Vulcanary installed (or `PYTHONPATH=src`):

```text
python -m pip install -r tests/contracts/requirements.txt
python -m unittest discover -s tests -p test_report_contracts.py -v
python -m unittest discover -s tests/contracts -p test_schemas.py -v
```

The separate schema suite is **mandatory in CI** on all supported platform/Python
matrix entries. Missing validators fail; they are not silently skipped. The wheel
still has zero runtime dependencies. Upstream schema bytes and license notices are
vendored under `tests/contracts/upstream/`, with immutable source URLs and SHA-256
hashes in `upstream-sources.json`. Unknown schema references fail closed; validation
never downloads schemas. Format checking is enabled and tested, as is the external
CycloneDX SPDX-license reference. Schema validation does not prove all semantic
requirements of a specification or that a reported vulnerability is real.

## OpenVEX corrections in 0.61

Validating against the official schema exposed pre-existing nonconformance:
`product` was an unsupported top-level field, `affected` statements lacked the
required `action_statement`, and an empty statements array is not allowed.

This release removes the nonstandard `product` field and adds remediation text.
This is an intentional compatibility correction for consumers of older Vulcanary
OpenVEX output; the repository argument remains accepted by the Python API.
Products remain identified by purl within each statement. Finding fingerprints,
severity, and policy outcomes are unchanged.

When no dependency advisory can produce a statement, the Python API raises
`NoVexStatements`; the authenticated dashboard returns HTTP 422 with code
`no_vex_statements`. The CLI warns and creates no OpenVEX file, excluding it from
provenance. If that destination already exists, it is preserved and the CLI returns
export error 2 to avoid presenting stale output as a new scan. Use a fresh output
path, normalized JSON, or an SBOM for a clean scan. No fabricated `not_affected`
statement is emitted. No OpenVEX file is not a claim of safety.
