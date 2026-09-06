# Steampipe → Stave Mapping Contracts

One YAML file per asset type. Each maps Steampipe table columns to
Stave observation property paths. The YAML is the contract — any agent
in any language can read it and produce a conforming `obs.v0.1`
snapshot.

## File layout

```
contracts/steampipe/
├── README.md
└── <asset_type>.yaml          one per Stave asset type
```

Filename matches the `asset_type` field inside the YAML and the
canonical asset-type schema name at
`schemas/observation/v1/asset-types/<asset_type>.schema.json`.

## Schema

Each YAML declares:

| Field | Purpose |
|---|---|
| `asset_type` | Stave asset type (e.g. `aws_s3_bucket`) |
| `steampipe_table` | Source Steampipe table name |
| `schema_version` | Target observation schema version (`obs.v0.1`) |
| `asset_id_column` | Steampipe column whose value becomes the asset id |
| `asset_id_fallback_template` | Filled when the id column is null; vars in `{braces}` reference other columns in the same row |
| `vendor` | Asset vendor string (`aws`, `gcp`, `azure`) |
| `operations` | Ordered list of operations that build the asset's `properties` block |

### Operation kinds

`operations:` is processed in declared YAML order. Each entry writes
one property path. Later operations may read paths written by earlier
ones (required for `computed`, optional elsewhere). YAML key order is
preserved into JSON output order, so authors control byte-for-byte
shape.

#### `field` — direct column → property mapping

```yaml
- kind: field
  path: properties.storage.name        # target Stave path
  column: name                         # source Steampipe column
  coerce: bool                         # optional: bool|str|int|float
  default: false                       # optional: used when column is null/missing
  use_asset_id: true                   # optional: replace column value with the computed asset id
  type: dict                           # optional: force non-dict (including null) to {}
```

#### `static` — fixed value (no column lookup)

```yaml
- kind: static
  path: properties.storage.kind
  value: bucket
```

#### `extract` — nested-JSON value from a JSON-shaped column

```yaml
- kind: extract
  path: properties.storage.encryption.algorithm
  column: server_side_encryption_configuration
  json_path: "Rules.0.ApplyServerSideEncryptionByDefault.SSEAlgorithm"
  key_variants:                       # optional: PascalCase ↔ snake_case fallback
    Rules: rules
    SSEAlgorithm: sse_algorithm
  default: "none"
```

`json_path` is dot-segmented. Numeric segments are list indices.
`key_variants` maps canonical key → fallback key tried when the
canonical one is absent — Steampipe plugins sometimes flatten the
AWS API's PascalCase to snake_case.

#### `computed` — derive from already-populated property paths

```yaml
- kind: computed
  path: properties.storage.controls.public_access_fully_blocked
  op: all                              # all | any (boolean reduction)
  inputs:
    - properties.storage.controls.public_access_block.block_public_acls
    - properties.storage.controls.public_access_block.block_public_policy
    - properties.storage.controls.public_access_block.ignore_public_acls
    - properties.storage.controls.public_access_block.restrict_public_buckets
```

Inputs are property paths set by earlier operations. The `op` reduces
their values to a single boolean.

## For agents

Read the YAML for the target asset type. Process `operations` in
order. For each operation, write the resolved value to the named
`path` inside the asset's `properties` object. The output is an
`obs.v0.1` snapshot — pass it through `stave lint --strict` to
confirm conformance.

The deterministic loader in `examples/agents/stave_transform.py`
demonstrates the four operation kinds; any other implementation that
honours the same shape produces the same output.

## Adding a new mapping

1. **Discover the property paths Stave reads for the type.**
   ```bash
   stave forge paths --asset-type <type> --snapshot example.obs.json
   ```
   Shows every path the catalog's predicates read on that type, with
   inferred types and presence counts.

2. **Inspect the Steampipe columns.**
   ```bash
   steampipe query "select * from <table> limit 1"
   ```
   Or read the plugin docs for the column list.

3. **Author `<asset_type>.yaml`.** Start with `field` ops for direct
   column-to-path mappings. Add `extract` ops for nested JSON. Add
   `static` ops for shape constants (`properties.storage.kind: bucket`).
   Add `computed` ops last for derived flags.

4. **Validate end-to-end.**
   ```bash
   python3 examples/agents/stave_transform.py \
     --input raw_rows.json \
     --asset-type <type> \
     --output ./obs/ \
     --validate
   ```
   `--validate` runs `stave lint --strict` on the produced
   snapshot. Iterate until validation passes.

## Source of truth

The per-asset JSON Schema at
`schemas/observation/v1/asset-types/<asset_type>.schema.json` defines
which property paths are valid. These mapping files define how to
PRODUCE conforming observations from Steampipe. A mapping that writes
an unrecognised path will fail `stave lint`.

## What lives where

- **This directory** — Steampipe → Stave mappings. Sibling directories
  (`contracts/aws-config/`, `contracts/terraform-state/`) hold mappings
  for other sources. Each source gets its own contract.
- **`schemas/observation/v1/`** — the target schema every mapping must
  satisfy. Don't edit; regenerate via `internal/tools/genassetschemas`
  when the catalog changes.
- **`examples/agents/stave_transform.py`** — the Python reference
  loader. Implements the four operation kinds; other agents can do the
  same in any language.
- **`internal/controldata/`** — control metadata. NOT for integration
  contracts. Don't put files here.
