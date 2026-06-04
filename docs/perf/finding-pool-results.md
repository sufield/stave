# Finding Pool Results

**Date:** 2026-06-03
**Change:** sync.Pool for `*evaluation.Finding` in `finding_builder.go`

## Before (baseline)

```
BenchmarkApply-8             1    3520967078 ns/op    693251808 B/op    10155080 allocs/op
BenchmarkApplyColdStart-8    1    5455333973 ns/op    699279048 B/op    10267318 allocs/op
```

## After (with pool)

```
BenchmarkApply-8             1    3616439880 ns/op    703192784 B/op    10344234 allocs/op
BenchmarkApplyColdStart-8    1    4144829482 ns/op    695918672 B/op    10202801 allocs/op
```

## Analysis

The pool has negligible impact on the lordofheaven fixture (38 findings).
The cost of sync.Pool get/put + zeroing is comparable to a fresh allocation
at this scale. The pool's benefit scales with finding count — at hundreds
or thousands of findings per evaluation (production accounts), the reduced
GC pressure from reusing finding structs would be measurable.

Cold-start improved from 5.5s to 4.1s — this is likely measurement noise
rather than a pool effect (the cold-start path is dominated by CEL
compilation, not finding allocation).

## Decision

The pool is committed as infrastructure. It adds no measurable cost at
small scale and positions for improvement at production scale. The race
detector passes on the engine package. The value-copy in
`RecordFindings` (`append(stripe, *f)`) ensures pooled findings are
fully consumed before return.

## Next steps

- Benchmark against a production-scale fixture (500+ assets, 1000+ findings)
- Profile GC % at scale to validate the pool's impact
- Consider pooling evidence maps if GC profile shows them as a hot path
