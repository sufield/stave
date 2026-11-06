---
name: writing-steampipe-mappings
description: Connect a new cloud data source to Stave by authoring a Steampipe → Stave observation mapping
triggers:
  - Steampipe mapping
  - collector mapping
  - connect a data source
  - new asset type
  - observation transform
  - field map
  - cloud data adapter
requires:
  - stave (go install github.com/sufield/stave@latest)
  - steampipe (brew install turbot/tap/steampipe)
---

# Writing Steampipe Mappings

Announce: *"I'm using the writing-steampipe-mappings skill to connect
this data source to Stave."*

## When to use this skill

- An asset type you need to evaluate has no `contracts/steampipe/*.yaml`
  mapping
- `stave validate` rejects your observation because required properties
  are missing (and the values exist in Steampipe rows the mapping
  doesn't yet project)
- The catalog reads a property the existing mapping doesn't populate

If the misconfiguration to detect is the issue and the mapping already
exists → use `stave:writing-stave-controls`.
If the task is *running existing mappings* → use
`stave:verifying-cloud-security`.

## Prerequisites

```bash
go install github.com/sufield/stave@latest
brew install turbot/tap/steampipe
steampipe plugin install aws
```

## Workflow

### Phase 1 — Identify the target asset type

```bash
stave contract show --list --format json | jq -r '.types[] | select(.steampipe_mapping == false) | .asset_type'
```

That's the set of asset types with NO existing mapping. Pick the one
your task needs.

For asset types not in the catalog at all, you'll need a new asset-type
schema first — that's a code change, out of scope for this skill.

### Phase 2 — Read the Stave-side contract

```bash
stave contract show --asset-type aws_kms_key --format json > /tmp/contract.json
jq '.property_paths[].path' /tmp/contract.json | head -20
```

These are the property paths controls read. Your mapping must populate
the high-priority ones.

### Phase 3 — Discover the Steampipe schema

```bash
steampipe query "
  SELECT column_name, data_type
  FROM information_schema.columns
  WHERE table_name = 'aws_kms_key'
  ORDER BY column_name
" --output json > /tmp/steampipe-cols.json
```

For complex columns (JSON-shaped), inspect a sample row:

```bash
steampipe query "SELECT * FROM aws_kms_key LIMIT 1" --output json | jq '.[0]'
```

### Phase 4 — Author the mapping YAML

Use the template at `mapping-template.yaml` next to this skill. The
structural shape:

```yaml
asset_type: aws_kms_key
steampipe_table: aws_kms_key
schema_version: obs.v0.1
asset_id_column: arn
asset_id_fallback_template: "arn:aws:kms:{region}:{account_id}:key/{key_id}"
vendor: aws

operations:
  - kind: static
    path: properties.encryption.kind
    value: kms_key

  - kind: field
    path: properties.encryption.id
    column: arn
    use_asset_id: true

  - kind: field
    path: properties.encryption.key_state
    column: key_state

  - kind: field
    path: properties.encryption.rotation_enabled
    column: key_rotation_enabled
    coerce: bool
    default: false

  - kind: extract
    path: properties.encryption.policy.has_external_principals
    column: policy
    json_path: "Statement.0.Principal.AWS"
    key_variants:
      Statement: statement
      Principal: principal
    default: false
```

Operation kinds:

| Kind | What it does | Required subfields |
|---|---|---|
| `field` | Direct column → property path | `column` |
| `static` | Constant value | `value` |
| `extract` | Pull a nested value from a JSON-shaped column | `column`, `json_path` |
| `computed` | Boolean reduction over previously-populated paths | `op` (any/all), `inputs` |

### Phase 5 — Validate the mapping structurally

Before running the mapping, check it for structural / coverage problems:

```bash
stave validate-mapping --file contracts/steampipe/aws_kms_key.yaml \
    --format json | jq '{
      result: .overall_status,
      structural_errors: [.structural[] | select(.severity == "error")] | length,
      schema_warnings: .schema | length,
      catalog_coverage: .coverage.percent_populated
    }'
```

**Checkpoint 1: `overall_status == "VALID"`.** Structural errors must
be zero before running the transform. The catalog coverage number tells
you what fraction of the catalog's read paths the mapping populates —
not a pass/fail, but a measure of how thoroughly your mapping covers
the asset type.

### Phase 6 — Run the transform end-to-end

```bash
# Sample raw rows
steampipe query "SELECT * FROM aws_kms_key LIMIT 5" --output json > raw.json

# Transform
python3 examples/agents/stave_transform.py \
    --input raw.json \
    --asset-type aws_kms_key \
    --output observations/

# Validate the OUTPUT
stave validate --in observations/*.obs.json --kind observation --strict
```

**Checkpoint 2: `stave validate` exits 0** on every emitted observation.

### Phase 7 — Evaluate to confirm controls fire correctly

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
stave apply --observations ./observations \
    --eval-time $NOW --format json \
    | jq '.findings | length'
```

If your test data has known-unsafe shapes, the expected controls should
fire. If they don't, your mapping isn't populating the properties those
controls read — look at the validate-mapping report's `catalog_coverage`
section for unpopulated paths.

**Checkpoint 3:** the controls you expect to fire on your test data
actually fire. The findings list is non-empty if and only if your test
data has unsafe shapes.

## Key principles

- **Validate the mapping structurally before running it.**
  `stave validate-mapping` is faster than waiting for `stave apply` to
  surface mapping bugs as evaluation errors.
- **Operation order matters.** Operations process in YAML declaration
  order; `computed` operations can read paths set by earlier `field`
  operations. JSON object key order in the output matches operation
  order — useful for byte-stable golden tests.
- **`field_variants` for case-insensitive JSON keys.** AWS policy JSON
  uses PascalCase (`Statement`, `Principal`); some Steampipe plugin
  versions return camelCase (`statement`, `principal`). Add both as
  `key_variants` so the extract is stable across plugin versions.
- **Test against a sparse fixture first.** Don't try to populate every
  property on the first pass. Get a minimal mapping working
  (`asset_id`, `kind`, one scalar), validate, then expand.

## Supporting files

- `mapping-template.yaml` — fillable starter with all four operation
  kinds shown

## Related skills

- `stave:verifying-cloud-security` — run the mapping you just authored
- `stave:writing-stave-controls` — author a control that reads the
  properties your mapping now populates
