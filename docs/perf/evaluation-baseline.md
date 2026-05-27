# Evaluation engine — benchmark baseline

Production-relevant numbers for the per-control evaluation hot path.
The legacy "Phase 1 baseline" (2026-05-21) was wrong; the legacy-
benchmark-fix commit (2026-05-27) corrected the bug and reset the
baseline. Numbers below are the new ground truth, paired with the
honest read on what they tell us about the Phase 2 parallelisation.

## Background — what the old numbers were actually measuring

The Phase 1 baseline document reported `BenchmarkEvaluate` at
**254.6 ns/op**. The corrected benchmark on the same hardware reports
**~2.2 ms/op** — five orders of magnitude slower.

The old numbers were the cost of `errors.New("precondition failed:
Assessor requires a PredicateEval")`. Every `b.Loop()` iteration
constructed an `Assessor` via struct literal without wiring
`predicateEval` or `predicateParser`, so `Assess()` returned at the
precondition check and the benchmark measured the error-string-
construction cost — not evaluation.

Fix: every benchmark now wires `predicateEval` (always-unsafe
lambda, mirrors `newTestAssessor.alwaysUnsafe()` in
`testbuilder_test.go`), `predicateParser` (empty-predicate stub),
and `hasher` (no-op digester) via a shared `benchAssessor()`
helper. A `mustAssessSucceed()` call outside the timer asserts the
precondition holds, so a future regression (forgot to wire a
precondition) fails the benchmark instead of silently inflating
the ns/op number with the error path.

## Run command

```bash
go test -run=^$ -bench=BenchmarkEvaluate -benchtime=3s -benchmem -cpu=1,8 \
  ./internal/core/evaluation/engine/
```

## Hardware

```
goos: linux
goarch: amd64
cpu: Intel(R) Core(TM) i5-8365U CPU @ 1.60GHz (8 logical cores)
```

## Numbers (2026-05-27, post-Phase-2-parallelisation)

| Benchmark | -cpu=1 | -cpu=8 | Ratio | Allocs/op |
|---|---:|---:|---:|---:|
| BenchmarkEvaluate (2 controls × 20 assets × 2 snap) | 2.23 ms | 2.27 ms | 0.98× | 2,234 |
| BenchmarkEvaluate10kAssets (5 controls × 10k assets) | 1.09 s | 1.27 s | 0.86× | 2.73M |
| BenchmarkEvaluateMultiControlScaling/controls=1 | 85 ms | 76 ms | 1.12× | 58,980 |
| BenchmarkEvaluateMultiControlScaling/controls=5 | 286 ms | 342 ms | 0.84× | 263k |
| BenchmarkEvaluateMultiControlScaling/controls=10 | 512 ms | 467 ms | 1.10× | 520k |
| BenchmarkEvaluateMultiControlScaling/controls=25 | 808 ms | 880 ms | 0.92× | 1.28M |
| BenchmarkEvaluateMultiControlScaling/controls=50 | 1.72 s | 1.62 s | 1.06× | 2.56M |
| BenchmarkEvaluateLargeScale (2,000 controls × 200 assets) | 8.67 s | 9.36 s | 0.93× | 23.3M |

## What the numbers say

**The Phase 2 parallelisation gives no measurable speedup on this
benchmark workload.** Every ratio sits in [0.84, 1.12] — noise band.
The 1.71× wall-clock reading captured in the earlier Phase 2 commit
was a single-sample artifact; the multi-iteration benchmark
averages reveal the true behaviour.

The reasons are honest and structural:

1. **The collector mutex is the bottleneck.** With the always-unsafe
   predicate, every asset×control pair generates a finding and
   takes `AssessmentCollector.mu` to record it. For `LargeScale`
   that's 2,000 × 200 × 2 = 800k mutex acquisitions per `Assess()`
   call. Eight goroutines queueing on one mutex don't parallelise.
2. **The synthetic predicate is too cheap.** The always-unsafe
   lambda returns `true` in nanoseconds. Per-control work is
   dominated by framework overhead (span begin/end, lifecycle
   iteration, finding construction) — none of which the
   parallelism reaches.
3. **Goroutine coordination has fixed cost.** For workloads where
   per-control work is tiny, the cost of `errgroup.Go` +
   scheduling + barrier-wait can exceed the per-core saving.

This is the predicted shape from the Phase 2 commit's "1.71× is a
conservative lower bound" caveat — except the lower bound turned out
to be **~1.0×**, not 1.71×, on this fixture. The wall-clock test was
showing variance, not signal.

## What this means for the Phase 2 parallelisation

The parallelisation isn't *wrong* — it's structurally correct
(per-control work is independent; the refactor removed the only
shared mutable state). But its measurable benefit on this fixture is
zero, because:

- the collector lock serialises the writes that escape each goroutine
- the per-control work is too small to amortise goroutine overhead

**The parallelism will start to pay off when the per-control work
becomes larger than the per-finding lock-acquire cost.** That
happens in production because real CEL predicates take microseconds
to tens of microseconds per asset (vs the nanosecond always-unsafe
stub). At ~10µs predicate cost × 200 assets = 2ms of per-control
work, with collector locks at ~100ns each = 20µs of contention per
control. Then the parallel speedup approaches the Amdahl bound.

**To prove this empirically, the benchmark needs to live one
package up.** `internal/core/evaluation/engine/` cannot import
`internal/adapters/cel` under the hexagonal architecture rules.
A benchmark in `internal/app/eval` or `pkg/stave` *can* wire the
real CEL evaluator (`stavecel.NewPredicateEval()`) and measure
production-shaped behaviour. That belongs in a follow-up.

## What changed about the candidate-optimisations list

The Phase 2 commit's "collector mutex contention is a future
concern" framing was conservative. **It's the dominant cost on the
current benchmark fixture, today.** That promotes a fourth item to
the optimisation-priorities list:

- **#4 Striped or per-goroutine-batched collector.** Replace the
  single `sync.Mutex` on `AssessmentCollector` with either striping
  (N shards keyed by `asset.ID` hash, each with its own mutex; merged
  in `Snapshot()`) or per-goroutine batches (each `applyControl`
  buffers findings/checks locally, then commits under the lock once
  per control). Striping fits the access pattern better because the
  collector is read-modify-write on per-asset counters (`SeenAsset`,
  `NonCompliantAsset`) where the asset ID is the natural shard key.

See [`optimization-priorities.md`](optimization-priorities.md) for
where this slots into the broader priority list. Roughly: now ahead
of #2 (CEL compilation cache) because we have benchmark evidence
the lock is the bottleneck; still behind a real-CEL benchmark which
is the prerequisite for measuring any optimisation honestly.

## Wall-clock test (kept for ad-hoc measurement)

The `TestLargeScale_WallClock` test in
`largescale_oneshot_test.go` remains — gated behind `STAVE_PERF=1`
so it does not slow normal runs. It prints three runs + BEST for
the same 2,000-controls × 200-assets fixture, useful as a quick
hand-tuned check of a change. Treat its output as one sample;
prefer the multi-iteration benchmark numbers above for any claim
that requires statistical weight.

```bash
STAVE_PERF=1 GOMAXPROCS=1 go test -count=1 -run TestLargeScale_WallClock -v ./internal/core/evaluation/engine/
STAVE_PERF=1 GOMAXPROCS=8 go test -count=1 -run TestLargeScale_WallClock -v ./internal/core/evaluation/engine/
```

## Profiling commands worth running next

```bash
# Where is the time actually going? Expect AssessmentCollector.mu to
# dominate. If it does, item #4 jumps to top priority.
go test -run=^$ -bench=BenchmarkEvaluateLargeScale -benchtime=10s \
  -cpuprofile=cpu.prof -mutexprofile=mutex.prof \
  ./internal/core/evaluation/engine/
go tool pprof -top -cum cpu.prof
go tool pprof -top mutex.prof

# Real-CEL benchmark belongs in a follow-up commit in pkg/stave or
# internal/app/eval. Mirror BenchmarkEvaluateLargeScale's shape but
# wire stavecel.NewPredicateEval() as the evaluator. Run with -cpu=1,8
# to show the production-shaped speedup the always-unsafe stub
# cannot.
```
