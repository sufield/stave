# Operator Contract

Three commands verify correctness after any change:

```bash
# 1. Unit tests (includes schema sync)
cd stave && make test

# 2. End-to-end S3 scenario tests
cd stave && make e2e-s3

# 3. Full build (schema sync + binary)
cd stave && make build
```

All three must pass before merging any refactor commit.
