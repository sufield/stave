# Evaluation engine — sequential baseline (Phase 1)

Baseline numbers for the sequential evaluation loop, captured 2026-05-21
before any parallelism work landed. The phase-2 refactor (move `activeSpan`
to a per-`applyControl` local, remove the `applyControlInUse` guard) and
the phase-3 worker-pool change should be measured against these.

## Run command

```bash
go test -run=^$ -bench=BenchmarkEvaluate -benchmem -benchtime=3s \
  ./internal/core/evaluation/engine/
```

## Hardware

```
goos: linux
goarch: amd64
cpu: Intel(R) Core(TM) i5-8365U CPU @ 1.60GHz (8 logical cores)
```

## Numbers (2026-05-21)

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| BenchmarkEvaluate | 254.6 | 16 | 1 |
| BenchmarkEvaluate10kAssets | 205.9 | 16 | 1 |
| BenchmarkEvaluateMultiControlScaling/controls=1 | 252.5 | 16 | 1 |
| BenchmarkEvaluateMultiControlScaling/controls=5 | 240.5 | 16 | 1 |
| BenchmarkEvaluateMultiControlScaling/controls=10 | 250.6 | 16 | 1 |
| BenchmarkEvaluateMultiControlScaling/controls=25 | 244.5 | 16 | 1 |
| BenchmarkEvaluateMultiControlScaling/controls=50 | 265.2 | 16 | 1 |

## What these numbers tell us

The inner evaluation loop is fast — sub-microsecond per asset×control pair,
flat under MultiControlScaling from 1 → 50 controls. If the production
runtime is slow against the 2,650-control catalog, the bottleneck is
**not** in the per-control evaluation loop. Candidate suspects worth
profiling before assuming parallelism is the right fix:

1. **Observation loading + schema validation.** `internal/contracts/validator`
   is called per file at load time. Worth profiling against a large
   observation directory.
2. **Chain composition.** `internal/core/evaluation/risk/chain_engine.go`
   groups failing controls by `scope_field`. Worst case is O(failures ×
   chains × scope-field-resolutions). Not benchmarked yet.
3. **Lifecycle index construction.** `BuildIdentityIndex(sequenced)` runs
   once per call but is O(asset_count) and may dominate large snapshots.
4. **Catalog load + predicate compilation.** Done once per CLI invocation
   but visible if the binary is invoked many times (e.g. in a tight
   integration loop).

## Phase-2 / phase-3 acceptance criteria

When parallelism lands, the same benchmark suite should show:

- **No regression** in single-control case (`controls=1`, `Evaluate`) — the
  parallel overhead must not cost more than it saves on the trivial path.
- **Linear-to-sub-linear scaling** of the new
  `BenchmarkEvaluateLargeScale` (2,000+ controls × 100+ assets) on an
  8-core machine. Expected ratio: ~3-5× speedup if the per-control work
  is genuinely parallelizable.
- **Determinism preserved.** The output of two runs against the same
  snapshot must be byte-equal. The proof is the existing
  `cmd/apply/verify` test — it must still pass post-parallelism.

## Profiling commands worth running before phase 2

```bash
# Where is the time actually going in a production-shaped run?
go test -run=^$ -bench=BenchmarkEvaluate10kAssets -benchtime=10s \
  -cpuprofile=cpu.prof -memprofile=mem.prof \
  ./internal/core/evaluation/engine/
go tool pprof -top -cum cpu.prof

# Realistic catalog test — needs a new benchmark vs the synthetic 50-control one.
# Should be added in phase 2 alongside the parallelism work.
```
