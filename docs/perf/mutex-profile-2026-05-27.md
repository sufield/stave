# Mutex profile — BenchmarkEvaluateLargeScale, 2026-05-27

Captured to confirm or refute the hypothesis the previous baseline doc
identified: the Phase 2 parallelisation shows no speedup at the
benchmark workload because the single `sync.Mutex` on
`AssessmentCollector` serialises all the writes that escape each
goroutine.

**Result: confirmed.** Mutex delay is 99.74% on
`sync.(*Mutex).Unlock`, attributable in full to the collector's
`RecordX` methods.

## Run command

```bash
go test -run=^$ -bench=BenchmarkEvaluateLargeScale -benchtime=10s \
  -mutexprofile=/tmp/mutex.prof -cpuprofile=/tmp/cpu.prof \
  ./internal/core/evaluation/engine/
go tool pprof -top /tmp/mutex.prof
go tool pprof -top -cum /tmp/cpu.prof
```

## Hardware + fixture

```
goos: linux
goarch: amd64
cpu: Intel(R) Core(TM) i5-8365U CPU @ 1.60GHz (8 logical cores)
Fixture: BenchmarkEvaluateLargeScale (2,000 controls × 200 assets × 2 snapshots)
Run: 11.53 s / iteration, 7.16 GB allocated, 23.3M allocs
```

## Mutex profile — top sites

```
Showing nodes accounting for 50.22s, 99.74% of 50.35s total
Dropped 206 nodes (cum <= 0.25s)
      flat  flat%   sum%        cum   cum%
    50.22s 99.74% 99.74%     50.22s 99.74%  sync.(*Mutex).Unlock
         0     0% 99.74%     27.09s 53.79%  RecordFindings
         0     0% 99.74%     18.83s 37.40%  RecordCheck
         0     0% 99.74%      2.75s  5.46%  RecordSeenAsset
         0     0% 99.74%      1.56s  3.09%  RecordNonCompliantAsset
         0     0% 99.74%     50.30s 99.89%  (*Assessor).Assess.func1
         0     0% 99.74%     50.30s 99.89%  (*assessmentSession).applyControl
         0     0% 99.74%     50.30s 99.89%  errgroup.(*Group).Go.func1
```

**Reading the column meanings:**

- `flat` is the time the function itself was blocked on the mutex.
- `cum` is the time anything in the function's call subtree was
  blocked. Since `sync.(*Mutex).Unlock` is the only leaf with
  measured delay, every parent's `cum` is the share of total delay
  attributable to call paths through that parent.

**What the numbers say:**

- 99.74% of all blocking delay sits on the single `Mutex.Unlock`
  exit from the collector's `mu`. No other lock in the system
  shows up in the profile at all.
- Inside the goroutine-spanning section
  (`errgroup.(*Group).Go.func1 → applyControl`), every
  `RecordX` path attributes to `Unlock` cumulatively:
  - `RecordFindings`: 53.79%
  - `RecordCheck`: 37.40%
  - `RecordSeenAsset`: 5.46%
  - `RecordNonCompliantAsset`: 3.09%
  - **Sum: 99.74%** (= the total measured delay).
- The errgroup-launched goroutine (`Assess.func1`) accounts for
  99.89% cumulatively — the remaining 0.11% is the sequential
  setup phase before the goroutine pool starts.

This is unambiguous. The collector mutex is the single contention
site. Striping it removes the bottleneck.

## CPU profile — top sites (corroborating)

```
Showing nodes accounting for 51.39s, 81.11% of 63.36s total
Duration: 25.31s, Total samples = 63.36s (250.32%)
      flat  flat%   sum%        cum   cum%
     0.09s  0.14%  0.14%     25.61s 40.42%  runtime.systemstack
         0     0%  0.14%     24.88s 39.27%  (*Assessor).Assess.func1
     0.13s  0.21%  0.35%     24.87s 39.25%  applyControl
         0     0%  0.35%     22.52s 35.54%  runtime.gcBgMarkWorker
     0.16s  0.25%   0.6%     22.45s 35.43%  runtime.gcDrain
     0.09s  0.14%  0.74%     16.31s 25.74%  unsafeStateStrategy.Evaluate
     0.15s  0.24%  0.98%     13.82s 21.81%  emitViolationFinding
```

The CPU profile says two complementary things:

1. **GC is eating 35% of CPU.** Three lines (`gcBgMarkWorker`,
   `gcDrain`, `gcDrainMarkWorkerIdle`) attribute that share to GC
   mark work. With 23.3M allocations per benchmark iteration —
   most of those `*Finding` objects from `emitViolationFinding` —
   the GC mark phase has a lot to chase. Reducing per-finding
   allocations would compound with the collector-striping win.
2. **Actual evaluation work is small.** `unsafeStateStrategy.Evaluate`
   sits at 25.74% cumulative, `emitViolationFinding` at 21.81%. The
   per-control evaluation loop is roughly a quarter of total CPU
   time. The other three quarters are GC + lock-related runtime
   overhead — *exactly* the surfaces the always-unsafe stub fixture
   makes pathological.

## Implications

Three concrete next steps, in order of expected impact:

1. **Stripe `AssessmentCollector`** (item #4 in
   [`optimization-priorities.md`](optimization-priorities.md)).
   Replace the single `mu sync.Mutex` with N shards keyed by
   `asset.ID` hash. Each `RecordX` method picks the shard and
   takes only that shard's mutex. `Snapshot()` merges shards in
   sorted order so existing determinism guarantees hold.
   Expected impact: parallelism speedup unblocked. The Phase 2
   refactor already removed the only other serialisation point
   (the per-call `activeSpan` field); the mutex is the last one.

2. **Reduce per-finding allocations.** `emitViolationFinding`
   allocates a `*Finding` for every asset×control pair, plus
   evidence maps, plus span steps. A sync.Pool of `Finding`
   objects + arena-allocated evidence slices could trim a
   meaningful share of the 23M allocs/iter. This compounds with
   #1 because shorter critical sections + less GC pressure both
   help.

3. **Real-CEL benchmark.** The always-unsafe stub makes the
   findings path pathologically hot. Wiring `stavecel.NewPredicateEval()`
   in a benchmark one package up (`pkg/stave` or `internal/app/eval`,
   neither of which the hexagonal architecture rules block from
   importing the CEL adapter) would show the production-shaped
   speedup picture. The 1.71× wall-clock reading from the Phase 2
   commit was within single-sample variance — the multi-iteration
   benchmark needs a more realistic predicate to settle the
   speedup question.

## What this does NOT prove

The 99.74% mutex delay is on **this benchmark fixture**. Production
behaviour will differ in three ways that all favour the parallelism:

- **Real CEL predicates take microseconds, not nanoseconds.** The
  per-control work is larger, the relative cost of per-finding
  collector contention shrinks proportionally.
- **Most production controls don't fire on most production
  assets.** The always-unsafe fixture has 100% finding rate, which
  is pathological. Realistic find rates are typically <10%, so the
  RecordX hot path runs <10% as often.
- **Production has many more controls than benchmarks.** 2,662
  controls × the realistic find rate puts more independent work in
  flight for the same lock pressure, so per-goroutine work
  amortises better.

The honest read: **the lock is *definitely* the bottleneck on this
fixture; it is *probably* also the bottleneck in production
because of #2**. Striping wins both cases. The next-most-likely
contender (GC pressure) also gets cheaper after striping because
shorter critical sections mean less memory live at any one moment.
