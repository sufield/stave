# Developer Workflow

## Getting data into Stave

Stave evaluates `obs.v0.1` observations and never calls cloud APIs itself.
Getting your data into that format is two steps, and **collection stays
external** — only conversion has a built-in default:

1. **Collect** raw configuration (this calls cloud APIs, so it uses your
   tools and your credentials): the AWS CLI, [Steampipe](https://steampipe.io),
   Pulumi, Terraform state, etc.
2. **Convert** the raw snapshots into `obs.v0.1`. The default is built in —
   **`stave transform`** runs jq filters in-process to reshape common AWS
   resources, no extractor to write:

   ```bash
   # doctest:skip — requires raw snapshot data
   stave transform -i raw/ -o observations/
   ```

You can still skip `stave transform` and use an **external extractor** that
emits `obs.v0.1` directly — a Steampipe SQL query piped through `jq`,
CloudQuery, or your own. See [Building an Extractor](extractor-prompt.md) when
you need breadth beyond the built-in filters or a custom data source.

**`validate`** checks that observations are schema-compliant. Run it whenever
observations come from an external extractor to catch mistakes before `apply`.

### Recommended workflow

```bash
# doctest:skip — requires raw snapshot and observation data
# Built-in path: collect raw snapshots, then convert
stave transform -i raw/ -o my-obs/

# Or an external extractor produces obs.v0.1 JSON directly
./my-extractor.sh > my-obs/2026-03-15T000000Z.json

# Validate catches schema mistakes before evaluation
stave validate --controls controls/s3 --observations ./my-obs

# Evaluate
stave apply --controls controls/s3 --observations ./my-obs --max-unsafe 168h
```

The `validate` step acts as a safety net. Common issues it catches:

- Missing `captured_at` timestamp
- Wrong top-level structure (e.g., wrapping observations in a `"snapshots"` array)
- Invalid `schema_version`
