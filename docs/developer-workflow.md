# Developer Workflow

## Getting data into Stave

Stave evaluates `obs.v0.1` observations and never calls cloud APIs itself.
**Collection stays external** — you use your tools and your credentials
(the AWS CLI, [Steampipe](https://steampipe.io), Pulumi, Terraform state,
etc.) to produce raw configuration snapshots.

**`stave apply` auto-transforms raw AWS CLI JSON** in-memory, so the
default path is one step — no separate conversion needed:

```bash
# doctest:skip — requires raw AWS CLI output
stave apply --observations raw/ --format text
```

To inspect the intermediate `obs.v0.1` output or run the conversion
separately, use **`stave transform`**:

```bash
# doctest:skip — requires raw AWS CLI output
stave transform -i raw/ -o observations/
```

You can also use an **external extractor** that emits `obs.v0.1`
directly. A Steampipe SQL query piped through `jq`, CloudQuery, or your
own. See [Building an Extractor](extractor-prompt.md) when you need breadth
beyond the built-in filters or a custom data source.

**`validate`** checks that observations are schema-compliant. Run it whenever
observations come from an external extractor to catch mistakes before `apply`.

### Recommended workflow

```bash
# doctest:skip — requires raw AWS CLI output and external extractor
# Default: point apply at raw snapshots directly
stave apply --observations raw/ --max-unsafe 168h

# Or an external extractor produces obs.v0.1 JSON directly
./my-extractor.sh > my-obs/2026-03-15T000000Z.json

# Validate catches schema mistakes for external extractors
stave lint --controls internal/controls/s3 --observations ./my-obs

# Evaluate external-extractor output
stave apply --controls internal/controls/s3 --observations ./my-obs --max-unsafe 168h
```

The `validate` step acts as a safety net. Common issues it catches:

- Missing `captured_at` timestamp
- Wrong top-level structure (e.g., wrapping observations in a `"snapshots"` array)
- Invalid `schema_version`
