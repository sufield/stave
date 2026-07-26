# Running Tests Without Melting Your Laptop

Stave's test suite spans ~200 packages. Running `make test` can saturate
every core and exhaust memory. The Makefile provides tiered targets that
match different development stages.

## Testing Pyramid

```
make test-fast        ← sub-minute, -short (skip e2e/golden)
make test-changed     ← only git-modified packages, race-checked
make test-pkg PKG=... ← single package, no sync overhead
make test-safe        ← full suite, resource-limited (-p 1, 2GB heap)
make test-integration ← internal/ fixture tests, no binary spawn
make test-e2e         ← binary-driven E2E (slowest)
make test             ← everything with race detector
make test-ci          ← CI: regenerate goldens then full suite
```

## Daily Workflow

**Iterating on a single package:**

```bash
make test-pkg PKG=./cmd/apply/...
```

Skips sync targets (fast), passes `-short`, 5-minute timeout.

**Before committing:**

```bash
make test-changed
```

Auto-discovers changed `.go` files from `git diff`, maps to packages,
runs with `-count=1 -race`. Falls back to `test-fast` if embedded-data
sources (controls/, schemas/) changed.

Compare against a branch instead of HEAD:

```bash
make test-changed BASE=main
```

**Laptop freezing on full suite:**

```bash
make test-safe
```

Serializes package execution (`-p 1`), caps in-package parallelism
(`-parallel 2`), and sets `GOMEMLIMIT=2GiB` to prevent OOM kills.

## Running Specific Tests

```bash
# By name (regex)
go test -v ./internal/core/evaluation/ -run TestChainEvaluation

# Specific subtest
go test -v ./internal/core/evaluation/ -run TestChainEvaluation/missing_property

# List without running
go test ./internal/core/evaluation/ -list '.*'

# Stop on first failure
go test -v -failfast ./pkg/stave/...
```

## Reproducing CI Failures

```bash
# Run the same package set as CI shard N (0-3)
make test-shard SHARD=0   # enginetest (heaviest)
make test-shard SHARD=1   # cmd/stave + graph + cel
make test-shard SHARD=2   # controls/builtin + pack + pkg/stave + cmd/apply
make test-shard SHARD=3   # everything else
```

## Test Separation

**`-short` flag:** Tests that call `testing.Short()` self-skip in
`test-fast`. Use for tests that are slow but self-contained.

**Build tags:** `test-docs` uses `-tags=integration` for tests that
require the built binary. Regular `go test ./...` skips them.

## Cache Control

Go caches test results by default. Force a clean run:

```bash
go test -count=1 ./...
```

`test-changed` and `test-docs` pass `-count=1` automatically. Skip it
during iterative development (cache makes unchanged packages instant).

## Race Detection

`make test` includes `-race`. For targeted race checking:

```bash
go test -race ./internal/core/evaluation/...
```

Combine with `-p 1` if race detection causes OOM on a large scope.
