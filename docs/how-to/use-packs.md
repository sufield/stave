# Use Packs

Packs are scoped control bundles — a subset of the catalog grouped by
service, standard, or use case. Use them to evaluate just what matters.

## List available packs

```bash
stave packs list
stave packs show iam
```

## Run with a pack

```bash
# doctest:skip — requires observation data
stave apply --pack iam --observations ./snapshots/
stave apply --pack fedramp_moderate --observations ./snapshots/
```

54 built-in packs ship with the binary, covering individual services
(iam, s3, lambda, cognito, …) and compliance standards (fedramp_moderate).
