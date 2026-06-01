---
name: stave-write-your-first-control
description: Author, test, and verify a custom Stave control using the forge toolchain
triggers:
  - write a control
  - author a control
  - custom detection
  - add a security policy to Stave
  - new control YAML
  - forge a control
requires:
  - a built stave binary (run stave-setup first)
---

# stave-write-your-first-control

## What this skill does
Walks you through authoring a new control using the `forge` toolchain, then
proves it fires on the positive case and stays quiet on the negative case.

**Time:** ~20 minutes. **No AWS needed.**

Controls are YAML match rules (`unsafe_predicate:` with `all:`/`any:` groups of
`field`/`op`/`value`). CEL is the internal evaluation engine — you never write it.
The `forge` commands generate, test, and lint the YAML for you.

## Steps

### 1. State the property to detect
e.g. "An S3 bucket must have access logging enabled."

### 2. Discover available fields
Point `forge paths` at an observation snapshot to see what fields exist:
```
./stave forge paths --snapshot examples/demo-s3-public-read/fixtures/writeup-config/observations/2026-01-10T000000Z.json \
  --asset-type aws_s3_bucket
```
This lists every property path, its type, and values. Find the field for your property.

### 3. Test the predicate before writing anything
```
./stave forge preview --snapshot <same-snapshot> \
  --field properties.storage.logging.enabled --op eq --value false
```
`FAIL` means the predicate catches the unsafe state. `PASS` means the asset is safe.
If nothing fires on a known-unsafe snapshot, revise the predicate before proceeding.

### 4. Generate the control + fixtures
```
./stave forge new --non-interactive \
  --id CTL.S3.LOG.CUSTOM.001 \
  --name "S3 buckets must have access logging" \
  --field properties.storage.logging.enabled \
  --op eq --value false \
  --severity high \
  --domain exposure \
  --remediation "Enable S3 server access logging" \
  --out ~/my-controls/
```
This generates the control YAML AND pass/fail test fixtures in one step.

### 5. Hand-edit the YAML (what forge doesn't cover)
Open `~/my-controls/.../CTL.S3.LOG.CUSTOM.001.yaml` and add:
- `classification: state_assertion`
- `applicable_asset_types: [aws_s3_bucket]`
- `scope_tags: [aws, s3]`
- `observation_fields:` listing every field the predicate reads
- `defect:` / `infection:` / `failure:` narrative (what's wrong / how it spreads / what fails)
- `tests:` with VIOLATION and PASS inline fixtures

Use an existing control as reference for the shape:
```
cat controls/s3/logging/CTL.S3.LOG.001.yaml
```

### 6. TDD — verify pass/fail
```
./stave forge test \
  --control ~/my-controls/.../CTL.S3.LOG.CUSTOM.001.yaml \
  --pass <pass-fixture>.json \
  --fail <fail-fixture>.json
```
The fail fixture must produce VIOLATION. The pass fixture must not fire.

### 7. Lint
```
./stave forge lint --control ~/my-controls/ --semantic --strict
```
Must pass with 0 errors, 0 warnings. `--semantic` catches always-firing and never-firing predicates.

### 8. End-to-end proof
```
./stave apply --controls ~/my-controls --observations <obs-dir>/ \
  --now 2026-01-02T00:00:00Z
```
Your control fires alongside the built-in catalog.

## Success
You authored a control using the forge pipeline, gave it pass/fail tests, linted it,
and watched it fire on the positive case only. You can now encode org-specific policy
in Stave.

## Advanced: adding to the built-in catalog
Drop the YAML under `controls/<domain>/<aspect>/` and run `make build` to sync it into
the embedded catalog. See `docs/controls/authoring.md` for the full convention
(ID format, compliance mappings, evidence citations, the forge-to-PR pipeline).
