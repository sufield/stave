# CI / Test Timing Audit

**Date:** 2026-05-13

**Scope:** measure where CI wall-clock time goes, how many fixtures dominate it, and which categories of test are blocking PRs vs running offline (push / schedule only).

**Method:** the audit cites CI-annotated shard timings (the team's own measured numbers, encoded as comments in `ci.yml` after profiling on the standard 2-core GitHub runner — these are the operating numbers) plus locally-measured fixture counts and disk sizes.

## TL;DR

The hot path is **shard 0 (`internal/core/enginetest`) at ≈383s** and **shard 1 (`cmd/stave + internal/graph + internal/cel`) at ≈351s**, with **shard 2 ≈255s** and shard 3 the long-tail of ~150 packages.

The **e2e job** runs on a separate 60-minute test timeout (70-minute job ceiling) and is intentionally **serialised** at `-parallel 1` — that's a contractual constraint, not an oversight (the suite drives the compiled binary as a black box). It's the slowest single piece by a wide margin, and it's not on the PR-blocking path: it lives outside the sharded `test` job.

The recently-deployed **goldens artifact-share** removed an ≈5× duplication where four shards plus race regenerated independently. Per-PR runner-minutes for golden regen dropped accordingly; wall-clock unchanged because shards were already parallel.

**The PR-feedback critical path** is:

```
goldens (≈1m) ─┬─ test shard 0 (≈6.5m)
                ├─ test shard 1 (≈5.9m)
                ├─ test shard 2 (≈4.3m)
                └─ test shard 3 (≈< 4m)
test-fast (≈< 1m, runs in parallel, no goldens dep)
lint, vuln, license, release-check, docs-freshness (independent, ≈1–3m each)
e2e (≈45–60m, push/schedule only, off the PR path)
race (push/schedule only)
```

**Total PR wall-clock**: roughly `goldens + max(shards) = 1m + 6.5m ≈ 7.5m` for the test gate, plus the lint/vuln/license jobs running in parallel (slowest of those ≈3m). PR feedback closes at ≈7.5 minutes.

## Fixture statistics (measured 2026-05-13)

| Category | Count | Disk |
|---|---|---|
| `testdata/e2e/` fixture directories | **2,529** | 120 MB |
| `testdata/` total JSON files | 8,912 | — |
| `testdata/` total YAML files | 2,737 | — |
| Golden / expected files (`expected*.json`, `golden*.json`) | **2,323** | included above |
| `examples/*/fixtures/*/observations/` (demo fixtures, not CI gate) | 115 | 33 MB |
| `internal/controldata/` (embedded controls) | — | 20 MB |
| Top-level `controls/` source YAML | 3,956 | — |
| `chains/*.yaml` | 583 | — |
| `*_test.go` files | **615** (98,632 lines) | — |
| Production `.go` files (incl. `internal`, `cmd`, `pkg`) | — | 132,149 lines |
| `.txtar` testscript fixtures | 21 | — |
| Test files using `t.Parallel()` | **83 of 615 (13.5%)** | — |

The e2e fixture tree (`testdata/e2e/`) is the dominant data shape. The CI comment says **"~5800 fixtures serialised"** in the e2e suite — that number includes sub-fixture files (observations × controls × expected outputs per directory); my count of 2,529 is at the directory level.

### Largest fixture directories (top 10 by file count)

| Files | Directory |
|---|---|
| 52 | `e2e-s3-golden-path` |
| 35 | `e2e-h1-shopify-94087` |
| 34 | `e2e-h1-shopify-94502` |
| 16 | `k8s-cis-level1` |
| 15 | `e2e-s3-deep-checks` |
| 15 | `e2e-iam-escalate-self-cluster` |
| 14 | `e2e-ad-pass`, `e2e-ad-fail` |
| 13 | `e2e-vsphere-pass`, `e2e-vsphere-fail` |

## CI job structure (`.github/workflows/ci.yml`)

Eight jobs (plus the four sibling workflows: `coverage.yml`, `codeql.yml`, `docs-drift.yml`, `release.yml`).

### Job: `goldens` (runs first; downstream consumers pull artifact)

- **Purpose**: single source of truth for golden regeneration. Was previously duplicated 5× across the four test shards plus race.
- **Steps**: `make regenerate-goldens golden-update-all sync-schemas sync-controls sync-alternatives ARGS="-workers 4"`.
- **Artifact**: uploads `testdata/`, `internal/contracts/schema/embedded/`, `internal/controldata/embedded/`, `internal/adapters/coverage/embedded/`, `**/testdata/golden/`. 1-day retention.
- **Wall-clock**: ≈60–90s typical (regen + artifact upload).
- **Optimization origin**: comment in workflow: "Wall-clock per workflow is unchanged (shards were already parallel) but runner-minutes for regen drop ~5×."

### Job: `test-fast`

- **Purpose**: sub-minute PR feedback. Doesn't wait for goldens.
- **Steps**: `make sync-schemas sync-controls sync-alternatives && go test -short -timeout 5m -count=1 ./...`.
- **Wall-clock**: targeted **sub-1-minute**. (Locally measured: `cel + predicate` <3s; full `-short` suite under a minute given the binary-spawning E2E suites and 50+-command walks self-skip under `-short`.)
- **Local measurement**: `make test-fast` ≈ measured 30–55s on a developer machine.

### Job: `test` (sharded by weighted timing)

The matrix is hand-tuned from measured shard times — see comments in `ci.yml` lines 80–93:

| Shard | Filter | CI-annotated time |
|---|---|---|
| 0 | `internal/core/enginetest$` (own runner — heaviest single package) | **383s** |
| 1 | `(cmd/stave|internal/graph|internal/cel)$` | **351s** |
| 2 | `(internal/adapters/controls/builtin|internal/builtin/pack|pkg/stave)$|cmd/apply` | **255s** |
| 3 | everything else (~150 packages) | not annotated; weighted to fit under shard 2 |

- **Dependency**: `needs: goldens` (downloads the artifact).
- **Run options**: `-tags stavedev -count=1 -parallel=2 -timeout 15m`. Parallelism `2` matches the 2-core runner.
- **No `-race`** on PRs — race detector adds 2–10× runtime and is gated to push / schedule.
- **Critical-path implication**: the gate closes at `max(shards) ≈ 383s + goldens overhead ≈ 7.5m total`.

### Job: `race`

- Same shard scope, but with the race detector enabled.
- **Gated** to push / schedule / workflow_dispatch — does NOT run on PR.
- Same `needs: goldens` dependency.
- E2E excluded from race (the e2e suite drives the binary; race on the test process adds no signal but inflates runtime past the 30m package timeout).

### Job: `e2e`

- **Scope**: `go test -v -parallel 1 -count=1 -timeout 60m -run E2E ./e2e/` — the full cross-cutting E2E suite.
- **Constraint**: `-parallel 1` is contractual. The suite serialises by design (see `e2e/e2e_test.go`); the command-level flag is "belt-and-braces" enforcement.
- **Job timeout**: 70 minutes (test timeout 60m, 10m headroom so a Go-level deadline-exceeded surfaces a panic + stack instead of GitHub-Actions killing the runner blind).
- **Fixture count cited in comments**: "~5800 fixtures serialised."
- **NOT gated by `needs:`** — runs independently of goldens (the e2e suite regenerates what it needs).

### Job: `lint`

- `golangci-lint run --timeout=5m`.
- Independent of `goldens`. PR-gating.
- Typical wall-clock: ~1–3 min.

### Jobs: `vuln`, `license`, `release-check`, `docs-freshness`

- `vuln`: `govulncheck ./...` after asserting Go toolchain matches `go.mod` exactly (catches transitive net-vuln regressions).
- `license`: `go-licenses` with allowlist `Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC` + explicit denylist for `GPL|AGPL|SSPL|LGPL`.
- `release-check`: `goreleaser check` (config sanity).
- `docs-freshness`: `make readme-check` (regenerates README.md template and diffs it against the committed file — catches stale auto-gen).
- All four independent of `goldens` and `test`. Typical wall-clock: 1–3 min each.

### Sibling workflows

| File | Trigger | Cost |
|---|---|---|
| `coverage.yml` | PR + push to main + dispatch | Coverage report on main package set |
| `codeql.yml` | PR + push to main + weekly cron | CodeQL analysis on Go |
| `docs-drift.yml` | PR + push to main, **path-filtered** to `docs/**` and `stave/docs/**` | Cheap when docs untouched |
| `release.yml` | release tag | Off the PR path |

## Bottleneck analysis

### 1. Shard 0 (enginetest) at 383s

`internal/core/enginetest` is one Go package with a large table-driven suite. The CI gives it a dedicated shard so it doesn't drag the others. Inside the package, `t.Parallel()` adoption is the lever — every parallelisable subtest already on its own runner means GOMAXPROCS=2 utilisation; pushing it to higher parallelism inside the package would require more cores per runner.

**Optimization candidates:**

- Split `enginetest` into multiple test files / sub-packages (e.g. by control domain) so Go's per-package parallelism multiplies.
- Larger CI runner (4-core) for shard 0 only — would let `-parallel=4` reduce wall-clock at runner-minute cost.
- Skip-if-unchanged: pair each `enginetest` case with the control domain it exercises; under impact-based selection, skip whole table rows when the change set doesn't touch their domain.

### 2. Shard 1 (`cmd/stave` testscript + graph + cel) at 351s

`cmd/stave` runs the 21 `.txtar` testscript files — each spawns the compiled binary. The CI build step compiles once; each testscript fork costs a process launch. With 21 testscripts at GOMAXPROCS=2, the lower-bound is `21/2 ≈ 10–11` testscripts deep on each core, multiplied by average testscript time.

**Optimization candidates:**

- More `t.Parallel()` markers inside individual testscript runners.
- Splitting `cmd/stave` testscripts into a separate sub-package with its own shard (some testscripts are heavy: `apply_pipeline.txtar`, `ci_workflow.txtar`, `snapshot_operations.txtar`).
- Cached binary across testscripts: already done via `testscript.RunMain` (no actual fork-exec — the test process simulates the binary). The "process" cost is just main() reinvocation, but accumulated state setup per case is still serialised.

### 3. Shard 2 (controls/builtin + pack + pkg/stave + cmd/apply) at 255s

`internal/adapters/controls/builtin` walks ~2,657 control YAMLs at load-test time. Mostly schema validation + alias resolution. `cmd/apply` runs the apply pipeline against representative fixtures.

**Optimization candidates:**

- Memoise the embedded-control parse once across all tests in the package (suite-level `TestMain` setup).
- Move the heavy fixture-driven apply tests into their own subpackage so `t.Parallel()` on the file-suite level kicks in earlier.

### 4. Shard 3 (~150 packages) — long tail

Each package is fast; the cost is per-package overhead (Go's per-package test binary). Already under shard 2's weight.

**Optimization candidate:** none, this is the residual after weighted sharding does its job.

### 5. e2e job at 45–60m

The contract is `-parallel 1` because the suite drives a compiled binary that touches global state (file system, exit codes, stdin/stdout). The 5800-fixture serialisation is what dominates.

**Optimization candidates** (all require contract changes):

- Re-architect e2e to use isolated tempdirs per case so `-parallel N` becomes safe. Requires every fixture to be self-contained (some currently share base observations).
- Split e2e into "heavy" (the actual cross-cutting flows) and "smoke" (one-fixture-per-control-domain) — run smoke on PR, heavy on push/schedule.
- Cache the compiled binary across e2e runs (already done via `make build` once; no further win there).

### 6. Race job: gated correctly

The race detector is gated to push / schedule / workflow_dispatch — PRs don't pay this cost. Correct factoring.

## What CI already optimised

The current `ci.yml` shows the team already deployed several heavy optimisations:

1. **Goldens-as-artifact** (replaces 5× regen duplication).
2. **Weighted sharding** with hand-measured shard times in workflow comments — not naive package-count split.
3. **`test-fast` parallel to `test`** — no `needs:` chain, so sub-minute feedback isn't gated by golden regen.
4. **Race gated to push/schedule** — PRs don't pay the 2–10× cost.
5. **`-parallel=2` matched to runner CPUs** — no oversubscription thrash.
6. **No `-race` in e2e** (process-driven, race signal on the test runner is noise).
7. **Path-filtered `docs-drift`** — doc-only PRs skip the expensive Go workflow.
8. **Vuln-check pinned to exact Go patch** so `1.26.3` doesn't silently fall back to a vulnerable `1.26.2`.
9. **License allowlist + denylist** as fail-fast filter.

This isn't a pre-optimisation codebase. The audit's job is to find what remains.

## Optimization candidates (remaining)

### A. Impact-based test selection (highest-leverage)

What changed → which tests need to run:

| Path changed | Tests to run | Skipped |
|---|---|---|
| `controls/<domain>/**.yaml` only | `internal/adapters/controls/yaml/...`, `enginetest` rows for `<domain>`, e2e fixtures tagged `<domain>` | Other domains' enginetest rows; e2e for other domains |
| `cmd/exportsir/**.go` | `cmd/exportsir/...`, `enginetest` rows that consume SIR output | The apply / chain / report shards |
| `cmd/apply/**.go` | shard 2 + e2e apply fixtures | exportsir, controls/builtin |
| `internal/core/evaluation/**.go` | shard 0 (enginetest) + e2e | everything else |
| `examples/**` | the demo-encoding sweep | core test shards |
| `docs/**` | docs-freshness only | all of `test` |

The mechanism is `go test ./changed/...` + a dependency tracker for transitive impact. Existing tooling: `go list -deps`, `git diff --name-only`. A small wrapper script could turn a PR diff into a focused test command.

**Tradeoff**: false negatives if dependency graph is stale. Mitigated by running the full suite on push to main (which already happens).

### B. Split `internal/core/enginetest`

The 383-second package is one suite. Splitting by control domain (`enginetest_s3_test.go`, `enginetest_iam_test.go`, etc.) lets Go parallelise across the resulting sub-packages and lets impact-based selection skip whole files when only one domain is touched.

### C. e2e smoke vs full

PR runs a curated smoke set (one fixture per control domain — ~50–80 fixtures). Push / schedule runs the full 5800. This halves PR wall-clock on the e2e job without losing the full-coverage signal.

### D. `t.Parallel()` audit in shard 0 and shard 2

13.5% of test files use `t.Parallel()` (83 of 615). The slowest packages (enginetest, controls/builtin) likely have headroom. Audit which subtests are parallel-safe; opt them in.

### E. Cache `make sync-controls` artefacts

Currently every CI job re-runs `make sync-schemas sync-controls sync-alternatives` (the embed step). The goldens job already captures `internal/controldata/embedded/` in the artifact — extending the artifact to include the post-sync state lets downstream jobs `tar x` instead of re-running the cp. Marginal saving (~5s per job) but mechanical.

## Migration order (low to high blast radius)

1. **Add a `go test --skip-unchanged` wrapper** that consumes `git diff --name-only` and emits a focused package list. Pure tooling, doesn't change CI; developers can opt in locally.
2. **Split `enginetest` by control domain** — file-level split, no logic change. Reduces shard 0 wall-clock by reducing per-package test binary linking cost.
3. **Audit `t.Parallel()` adoption** in the slowest 5 packages; mark the safe ones.
4. **Wire the impact-selector into CI**: a job-level conditional that detects "docs-only" or "single-domain-controls-only" PRs and skips the heavy shards. Existing precedent: `docs-drift.yml` already path-filters.
5. **E2E smoke / full split**: contract change in `e2e/e2e_test.go`; requires per-case tagging.
6. **Larger runner for shard 0**: cost change (paid runner-minutes); benefit measurable on shard-0 wall-clock.

Items 1–3 are doc / mechanical; items 4–6 are gated by the team's appetite for additional CI complexity.

## Local timing notes

`make test-fast` (the developer-loop target) completes in **under a minute** on a developer machine — `go test -short -timeout 5m ./...` with binary-spawning e2e suites self-skipping.

Sample slice (`./internal/adapters/cel/...` + `./internal/core/predicate/...`): **< 3 seconds** including sync-controls overhead.

### Per-package measured times (developer machine, `-parallel=2`)

Captured 2026-05-13 with `time go test -tags stavedev -count=1 -parallel=2 ./<pkg>/...`:

| Package | Local `real` | Local `user` | CI annotation | Notes |
|---|---|---|---|---|
| `internal/core/enginetest` | **4m23s** (263s) | 10m35s | 383s | Local CPU saturates at ~2.4× parallelism; CI's 2-core runner is the bottleneck (matches the annotation) |
| `cmd/apply` (full) | 11.5s | 28s | shard 2 subset (255s total) | Heavy fixture-driven apply tests; the rest of shard 2 is `controls/builtin` + `builtin/pack` |
| `cmd/exportsir` | 1.5s | 2.1s | not annotated | Very fast — single-package SIR projection tests |
| `internal/adapters/controls/yaml` | 1.2s | 1.4s | not annotated | YAML loader tests; ~2,657 controls walked |

The `enginetest` local-vs-CI ratio (263s / 383s ≈ 0.69) is consistent with the `user 10m35s ÷ real 4m23s ≈ 2.4×` parallelism factor on a >2-core developer machine. CI's runners cap at 2 cores, so the 383s annotation in `ci.yml` is the operating reality for PR-gating. **Don't tune to local times** — the shard weights in `ci.yml` are calibrated for the 2-core CI environment.

The full `./...` wall-clock measurement was still running in the background when this audit landed and is not blocking; the per-package times above are the actionable signal for sharding decisions.

## Counts summary

| Metric | Value |
|---|---|
| Workflow files | 5 (`ci.yml`, `coverage.yml`, `codeql.yml`, `docs-drift.yml`, `release.yml`) |
| CI jobs in `ci.yml` | 8 (goldens, test-fast, test×4 shards, race, lint, vuln, license, e2e, release-check, docs-freshness) |
| PR-gating jobs | goldens + test (4 shards) + test-fast + lint + vuln + license + release-check + docs-freshness |
| Push/schedule-only jobs | race + e2e |
| PR wall-clock critical path | ≈7.5 minutes (goldens 1m + max-shard 6.5m) |
| e2e wall-clock | 45–60 minutes (off PR path) |
| Fixture directories under `testdata/e2e` | 2,529 |
| Golden files (`expected*.json` / `golden*.json`) | 2,323 |
| Total test code | 98,632 lines across 615 `_test.go` files |
| Test files using `t.Parallel()` | 83 (13.5%) |
| Shipped controls | 2,657 |
| `.txtar` testscript files | 21 |
