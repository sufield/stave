# Developer Workflow

## Extraction and validation

Extraction is external to Stave. You write your own extractor (in any language) that produces `obs.v0.1` JSON from your data source. See [Building an Extractor](extractor-prompt.md) for a jumpstart template, or use an existing extractor such as `stave-extractor`.

**`validate`** checks that observations are schema-compliant. Use it whenever observations come from an external extractor to catch mistakes before `apply`.

### Recommended workflow

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
