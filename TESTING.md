# Testing

Stave's test suite is structured as a pyramid. Use the lowest tier
that covers the change you made; reach higher only when you need
to.

## Tiers

| Target | Scope | Typical duration | When to run |
|--------|-------|------------------|-------------|
| `make test-fast` | `-short` across `./...` | sub-minute (cold), seconds (cached) | While iterating on a single change |
| `make test-integration` | `./internal`, `./cmd/apply` (no `-short`) | 1–3 minutes | Before opening a PR |
| `make test-e2e` | Builds the binary and runs `./e2e` + `./cmd/stave` testscript fixtures | 5–10 minutes | Before merging when you touched eval, output, or fixture-driven paths |
| `make test` | Everything, with `-race`, `-parallel 16`, `-tags stavedev` | 10–30 minutes | Final pre-merge check on a fast machine |
| `make test-ci` | `regenerate-goldens` + `golden-update-all` + `make test` | 30+ minutes | Reproduce CI locally |

The targets above call `sync-schemas`, `sync-controls`, and
`sync-alternatives` first so the embedded data matches the
source-of-truth `controls/`, `schemas/`, and `data/` directories.

### Fast-loop sync (local-only)

The three `sync-*` targets are **content-hash-gated**: each hashes
its source tree and skips the `rm`/`cp` when the hash matches a
cached value AND the destination still exists. On unchanged
source, the three syncs together cost ~100 ms instead of ~800 ms,
shaving most of the prelude off every `make test` / `make lint`
during iteration. The cache files (`.sync-*-hash`) are gitignored
— CI has no cache, so clean checkouts re-sync every time and
correctness is unchanged. To force a re-sync locally, delete the
relevant `.sync-*-hash` file.

### Incremental golden regeneration

`regenerate-goldens` accepts a name-filter regex via `ARGS`:

```bash
# Regenerate only S3-related fixtures
make regenerate-goldens ARGS="-filter s3"

# Regenerate one specific fixture
make regenerate-goldens ARGS="-filter s3-public-read-policy"
```

Use this when you touched a single domain's controls. Drop the
filter (`make regenerate-goldens`) only when an engine-wide change
could shift output across the catalog.

For in-process Go goldens (the ones updated via `UPDATE_GOLDEN=1`):

```bash
make golden-update PKG=./internal/profile/reporter/...    # one package
make golden-one    PKG=./internal/profile/reporter RUN=TestTextReporter_Golden
```

## `-short` flag behavior

A test that calls `testing.Short()` and `t.Skip(...)` self-skips
under `-short`. Stave uses this for:

- Tests that build and exec the stave binary (`./e2e`,
  `./cmd/stave/testdata/scripts/*.txtar`,
  `cmd/apply/profile_e2e_test.go`,
  `cmd/apply/verify/determinism_test.go`).
- Tests that walk every command in the tree
  (`cmd/clig_compliance_test.go`).
- Tests that load and evaluate every fixture in
  `testdata/e2e/` (`internal/adapters/cel/parallel_test.go`).
- Heavy integration tests in `cmd/apply` that load the HIPAA
  profile end-to-end (`cmd/apply/profile_e2e_test.go`).

If a test takes more than ~1s, gate it on `testing.Short()`.

## Focused runs during development

Run a single package: `go test ./internal/adapters/cel/...`

Run a single function: `go test -run TestCompile_EmptyFieldRule ./internal/adapters/cel/...`

Force a re-run (Go caches passing test results by default):
`go test -count=1 ./internal/adapters/cel/...`

Race detector for one package:
`go test -race ./internal/core/evaluation/engine/...`

## Goldens

Golden file diffs surface as test failures in `./e2e` and
`./cmd/apply` E2E suites. Regenerate via
`make regenerate-goldens`. The tool prints a categorized diff:

- `CLEAN` / `FINGERPRINT-ONLY` / `METADATA-ONLY`: safe to commit.
- `BEHAVIORAL` / `MIXED`: investigate before committing —
  detection behavior shifted; confirm the shift is intentional.

For a faster regen on a single fixture:
`make regenerate-goldens ARGS="-filter aws-s3-obs-public"`

## What's not cacheable

Go's test cache works for unchanged source + dependencies, but
specific tests force a fresh run:

- Tests using `t.Setenv(...)` — Go invalidates the cache.
- Tests that read the wall-clock time directly — none in the
  Stave core (the architecture-isolation test in `internal/app`
  enforces this), but check before adding.
- Tests using `testdata/` symlinks — file modtime changes
  invalidate cache entries.
- Anything CI runs with `-count=1` is *intentionally* never
  cached — used to defeat the test result cache when freshness
  matters more than runtime.

When you must defeat the cache: `go test -count=1 ...`

## CI parallelism and caching

CI (`.github/workflows/ci.yml`) is structured as parallel jobs:

- **`test-fast`** — `-short` across `./...` for sub-minute PR
  feedback. Runs independently of the sharded suite so it never
  waits behind the heavier jobs.
- **`test`** (sharded into 4) — full per-package coverage,
  weighted by measured runtimes. Each shard regenerates goldens
  fresh; goldens are discarded at job end so fingerprint churn
  never lands on PR diffs.
- **`race`** — full suite under the race detector; nightly +
  push events only.
- **`e2e`** — binary-driven golden suite; runs in parallel with
  the sharded `test` job.

`actions/setup-go` is invoked with `cache: true` in every job, so
the Go module download cache and build cache are restored from
the GitHub Actions cache between runs. Cache keying is
`go-version + go.sum`, so any dep change invalidates the
relevant entries.

Per-fixture golden regeneration uses the worker pool exposed by
`regengoldens`. CI passes `ARGS="-workers 4"` to bound the pool
to four concurrent fixtures per shard; raise it locally with
`make regenerate-goldens ARGS="-workers 8"` on a beefier
machine.
