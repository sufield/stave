# Optimization priorities — evaluation hot path

Priority-ranked plan for the evaluation hot path. Each item is
grounded in either shipped code or measured profile data. Items
flow top to bottom in recommended execution order.

## Completed

### ✅ Parallelize per-control evaluation

Shipped across four commits (2026-05-26 / 2026-05-27):

- `c95721fc2` — Phase 1: move `activeSpan` from session field to
  per-call parameter, remove `applyControlInUse` CAS guard.
- `9633fae41` — Phase 2: wrap per-control loop in `errgroup`
  bounded by `runtime.NumCPU()`.
- `4b158bf1f` — Phase 3: wall-clock measurement + `BenchmarkEvaluateLargeScale`.
- `5227d819d` — Legacy benchmark fix (uncovered that the previous
  baseline numbers were measuring an error-return path) +
  honest restatement of measured speedup as ~1.0× (noise band).

**Outcome:** structurally correct (`-race` clean across the engine,
downstream packages, and `pkg/stave`), but **no measurable
parallelism speedup on the benchmark workload** because the
collector mutex serialises every per-asset write. That blocker is
the new #1 below.

## Active priority

### 1. Stripe the `AssessmentCollector` mutex

**Evidence:** [`mutex-profile-2026-05-27.md`](mutex-profile-2026-05-27.md)
shows **99.74% of all blocking delay** sits on
`sync.(*Mutex).Unlock` from `AssessmentCollector.mu`. The lock is
the entire bottleneck.

**Change:** replace the single `mu sync.Mutex` + flat slices on
`AssessmentCollector` with N shards keyed by `asset.ID` hash. Each
`RecordX` method picks the shard for its asset and takes only that
shard's mutex. `Snapshot()` merges shards in sorted order so the
deterministic-output contract that `compileReport` depends on
remains intact.

**Shape:**

```go
type AssessmentCollector struct {
    stripes [16]*collectorStripe   // power-of-two for cheap shard lookup
    // Per-collector state that doesn't shard cleanly stays out of
    // the stripes (skippedControls, exemptedAssets).
}

type collectorStripe struct {
    mu       sync.Mutex
    findings []*evaluation.Finding
    checks   []evaluation.ResourceCheck
    seen     map[asset.ID]struct{}
    nc       map[asset.ID]struct{}
    exempt   map[asset.ID]struct{}
}

func (c *AssessmentCollector) RecordCheck(check evaluation.ResourceCheck) {
    s := c.stripes[stripeIndex(check.AssetID)]
    s.mu.Lock()
    s.checks = append(s.checks, check)
    s.mu.Unlock()
}

func (c *AssessmentCollector) Snapshot() CollectorSnapshot {
    // Sum/merge across stripes, then sort. Existing sort step in
    // compileReport keeps determinism guarantees.
}
```

**Stripe count:** 16 is the conventional choice — large enough to
decouple typical contention, small enough that the shard array
fits in one cache line. 64 is the next step up if 16 still shows
hot stripes under profile.

**Why striping over per-goroutine batching:** the natural shard
key is `asset.ID` (every `RecordX` already carries it). Batching
would require touching every call site to thread a batch through,
where striping is a drop-in change inside the collector. Same
correctness story (writes still serialise per shard), better
locality.

**Risk: Low-to-medium.** The collector's existing test surface
(via the engine integration tests) catches behavioural
regressions. The merge step in `Snapshot()` is the only new
sorting boundary — exercise with -race and verify the existing
determinism tests still pass byte-for-byte.

**Acceptance criteria:**
- All existing tests pass with `-race`.
- Mutex profile rerun shows total delay drops by at least 10×
  (the per-shard `Mutex.Unlock` shows up but no single shard
  dominates).
- `BenchmarkEvaluateLargeScale` shows measurable speedup at
  `-cpu=8` vs `-cpu=1` for the first time on this fixture.

**Do this first.** Every other item below is gated on getting
useful signal out of the benchmark, which requires the lock to
not be the dominant cost.

### 2. Real-CEL benchmark in `pkg/stave` or `internal/app/eval`

**Why it matters:** the `internal/core/evaluation/engine`
benchmarks must wire a stub `predicateEval` because the hexagonal
architecture rules forbid `internal/core/*` from importing
`internal/adapters/cel`. The always-unsafe stub the benchmarks use
returns `true` in nanoseconds, which makes the per-control work
pathologically small relative to coordination overhead — a fixture
that's fine for catching regressions in the framework code but
unable to show production-shaped behaviour.

**Change:** add a benchmark to a package that can import
`internal/adapters/cel`. `pkg/stave` is the natural home (it's the
facade layer; benchmarks there can call `stave.Apply` with a real
CEL evaluator wired in via the existing factory). Alternatively
`internal/app/eval` if a deeper-layer benchmark is wanted.

**Acceptance criteria:**
- Benchmark uses a representative subset of the shipped catalog
  (e.g., the IAM or S3 control pack) and a synthetic
  observation snapshot of comparable shape to a real
  `obs.v0.1` dump.
- Runs at `-cpu=1,8`. The ratio is the production-shaped speedup.
- Numbers committed alongside the benchmark in a paired doc.

**Do this second**, immediately after striping. The honest test
of whether the parallelism + striping combo wins in production
requires a fixture that looks like production.

## Lower priority

### 3. Reduce per-finding allocations

**Evidence:** CPU profile from
[`mutex-profile-2026-05-27.md`](mutex-profile-2026-05-27.md) shows
`runtime.gcBgMarkWorker` at 35.54% cumulative CPU. The benchmark
allocates 23.3M objects per iteration, most of them `*Finding`
values from `emitViolationFinding`.

**Change:** sync.Pool for `Finding` allocation; arena-style
slice allocators for evidence maps; struct-pack `Finding` to
reduce per-object overhead.

**Risk: Medium.** sync.Pool requires a clear ownership model
(every borrow must return; every return must clear sensitive
fields). Get this wrong and findings stomp on each other across
goroutines. The collector striping (item #1) helps by shortening
critical sections; this item compounds the GC win.

**Trigger:** after item #1, re-profile. If `gcBgMarkWorker` still
shows >20% cumulative CPU, this becomes the next target. If
striping alone drops it below that threshold, defer.

### 4. CEL compilation cache (persistent across runs)

**Evidence: none yet.** The hypothesis is that CI runs eat the
full CEL-compilation cost on every invocation (cold container,
no warm cache); for 2,662 predicates that's a non-trivial
fixed cost per run. But **no profile data confirms this is
the bottleneck**.

**Gate:** profile a real `stave apply` invocation against the
shipped 2,662-control catalog (after items #1 and #2 land). If
`cel.Compile` shows in the top CPU frames, build the cache. If
predicate evaluation dominates, defer.

**Risk: Medium.** `cel.Program` has no public serialisation API.
Two approaches:

1. **Cache parsed AST + re-typecheck on load.** Uses cel-go
   internals; version-pin and gate behind cel.Lib version
   checks.
2. **Cache expression strings, skip type-check on cache hit.**
   No dependency on cel-go internals; slower than #1 but
   still faster than full compilation.

`FingerprintPolicy()` already provides the invalidation
mechanism — catalog changes rotate the fingerprint, cache
expires.

### 5. Control→chain inverted index

**Evidence: none yet — speculative future-proofing.**

`DetectChains()` (`internal/app/eval/workflow.go:295`) currently
does O(chains × failures) map operations. An inverted index from
control IDs to the chains that mention them gives
O(failures × avg_chain_fan_out).

At current scale (622 chains today), this is not measurably hot.
**Trigger:** chain catalog crosses 1,000 OR profiling shows
`DetectChains` in the top CPU frames.

## Priority order, summarised

| # | Optimization | Status | Impact | Risk | Trigger |
|---|---|---|---|---|---|
| ✅ | Parallelise per-control evaluation | DONE | High structural, ~1× observed | Low | — |
| 1 | Stripe `AssessmentCollector` mutex | **Active** | Unblocks #✅ | Low-medium | Now — 99.74% mutex delay confirms |
| 2 | Real-CEL benchmark (`pkg/stave`) | Active | Honesty / measurement | Low | After #1 ships |
| 3 | Reduce per-finding allocations | Gated | Medium | Medium | Profile after #1; gates on gcBgMarkWorker >20% cum |
| 4 | CEL compilation cache | Gated | Med-high CI / Low interactive | Medium | Profile after #2; gates on `cel.Compile` in top CPU |
| 5 | Control→chain inverted index | Gated | Medium | Low | Chain catalog crosses 1,000 OR `DetectChains` in top CPU |

## Sequencing rationale

The previous version of this document ranked **CEL compilation cache
as #2 based on a hypothesis**. With actual profile data, the picture
is clearer:

- The Phase 2 parallelisation work landed and is structurally
  correct — but its measurable benefit is masked by the collector
  lock contention.
- **Striping the collector unblocks the speedup that's already in
  the code.** It's a higher impact-per-unit-work item than any
  speculative cache because we have direct evidence the lock
  dominates.
- Once striping lands, the bottleneck *will move* — either to GC
  (item #3), to CEL compilation (item #4), or somewhere new. Each
  of the lower items is gated on a profile rerun after #1 lands.

## Related

- [`evaluation-baseline.md`](evaluation-baseline.md) — current
  benchmark numbers (2026-05-27, post-Phase-2)
- [`mutex-profile-2026-05-27.md`](mutex-profile-2026-05-27.md) —
  the profile evidence for #1
- [`internal/core/evaluation/engine/assessor.go`](../../internal/core/evaluation/engine/assessor.go) — the
  Phase 2 parallelisation
- [`internal/core/evaluation/engine/collector.go`](../../internal/core/evaluation/engine/collector.go) — where
  the striping work happens
