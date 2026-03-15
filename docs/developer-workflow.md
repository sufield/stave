# Developer Workflow

## Why are `ingest` and `validate` separate commands?

They serve different personas in different workflows.

**`ingest`** converts raw cloud exports (AWS CLI JSON, Terraform plan output) into the `obs.v0.1` observation schema. It handles structural transformation — mapping vendor-specific fields to Stave's normalized format, setting `captured_at`, `source_type`, and `schema_version`. The output is schema-valid by construction.

**`validate`** checks that observations are schema-compliant. It exists for the case where users skip `ingest` and write observations by hand or with their own extractor.

| Path | Who creates observations | Needs `validate`? |
|---|---|---|
| `stave ingest` | Stave creates them | No — output is schema-valid by construction |
| Custom extractor (AWS CLI + jq, scripts) | User creates them | Yes — catches mistakes before `apply` |

If `ingest` also ran validation, it would need to know about all downstream control requirements — which fields are needed, which source types are supported, what the schema version expects. That couples the data pipeline to the evaluation engine. The current design follows the Unix principle: `ingest` transforms, `validate` checks, `apply` evaluates. Each does one thing.

### When to use each

**Using `stave ingest` (recommended for supported sources):**

```bash
stave ingest --source-dir ./aws-export --output-dir ./my-obs
stave apply --controls controls/s3 --observations ./my-obs --max-unsafe 168h
```

No `validate` step needed. Go straight from ingest to apply.

**Using a custom extractor (AWS CLI + jq, scripts, custom tools):**

```bash
# Your extractor produces observation JSON files
./my-extractor.sh > my-obs/2026-03-15T000000Z.json

# Validate catches schema mistakes before evaluation
stave validate --controls controls/s3 --observations ./my-obs

# Fix any issues in your extractor, then evaluate
stave apply --controls controls/s3 --observations ./my-obs --max-unsafe 168h
```

The `validate` step acts as a safety net. Common issues it catches:

- Missing `captured_at` timestamp
- Missing or unrecognized `source_type` (use `--allow-unknown-input` for custom types)
- Wrong top-level structure (e.g., wrapping observations in a `"snapshots"` array)
- Invalid `schema_version`

## Why does `ingest` not reject invalid input?

It does. `ingest` rejects structurally broken source files — invalid JSON, missing required vendor fields, unrecognized source directory layout. What it does not do is validate the *output* against the full `obs.v0.1` schema after transformation, because the transformation itself guarantees schema compliance. If `ingest` produces output that `validate` rejects, that is a bug in `ingest`.
