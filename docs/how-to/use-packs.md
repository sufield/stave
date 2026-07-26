# Use Packs

Packs are scoped control bundles — a subset of the catalog grouped by
service, standard, or use case. Use them to evaluate just what matters.

## List available packs

```bash
stave pack list
stave pack show iam
```

## Run with a pack

```bash
stave apply --pack entropy --observations testdata/e2e/e2e-01-violation/observations
stave apply --pack quick --observations testdata/e2e/e2e-01-violation/observations
```

Use `stave pack list` to see all available packs.
