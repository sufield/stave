# Developer Workflow

## Getting data into Stave

Stave evaluates `obs.v0.1` observations and never calls cloud APIs itself.
**Collection stays external** Use your tools and your credentials
(the AWS CLI, [Steampipe](https://steampipe.io), Pulumi, Terraform state,
etc.) to produce raw configuration snapshots.

Convert raw AWS CLI JSON to `obs.v0.1` using the **Lean 4 extractors**
(`iam-explainer/Stave/Extract/`), then evaluate:

```bash
# doctest:skip — requires obs.v0.1 observations
stave apply --observations observations/ --format text
```

You can also use an **external extractor** that emits `obs.v0.1`
directly. A Steampipe SQL query piped through `jq`, CloudQuery, or your
own. See [Building an Extractor](extractor-prompt.md) for custom data sources.

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
