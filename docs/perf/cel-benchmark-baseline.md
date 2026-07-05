# CEL Benchmark Baseline

**Date:** 2026-06-03
**Fixture:** lordofheaven (2 snapshots, multi-asset S3 evaluation)
**Catalog:** 2816 built-in controls
**Machine:** Linux x86_64, 8 CPUs

## Results

```
BenchmarkApply-8             1    3520967078 ns/op    693251808 B/op    10155080 allocs/op
BenchmarkApplyColdStart-8    1    5455333973 ns/op    699279048 B/op    10267318 allocs/op
```

| Metric | Warm | Cold |
|--------|------|------|
| Time | 3.52s | 5.46s |
| Heap allocated | 693 MB | 699 MB |
| Allocations | 10.2M | 10.3M |
| Cold-start overhead | — | +55% (CEL compile cache miss) |

## Observations

- **10M allocations per run** — the dominant cost. Each (control, asset)
  pair allocates findings, evidence maps, and observation slices.
- **Cold start adds ~2s** — CEL program compilation for 2816 controls.
  The warm path reuses the compile cache.
- **693 MB heap** — dominated by control catalog loading + per-finding
  allocations. A sync.Pool for findings would reduce both alloc count
  and GC pressure.

## Next steps

- Issue #3: pool `*evaluation.Finding` allocations via `sync.Pool`
- Measure with `-cpu=1,2,4,8` to validate collector striping benefit
- Profile with `go tool pprof` to identify top allocation sites
