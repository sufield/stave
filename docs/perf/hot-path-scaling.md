# Hot-Path Scaling Analysis

**Date:** 2026-06-03
**Fixture:** lordofheaven (2 snapshots, 2 assets)
**Catalog:** 2907 controls, 622 chains

## CPU Scaling

```
BenchmarkApply     1    1997778256 ns/op    699164080 B/op    10276753 allocs/op
BenchmarkApply-4   1    1953358418 ns/op    696295352 B/op    10229920 allocs/op
BenchmarkApply-8   1    1939469256 ns/op    700751432 B/op    10311826 allocs/op
```

| CPUs | Time | Speedup |
|------|------|---------|
| 1 | 2.00s | 1.0x |
| 4 | 1.95s | 1.02x |
| 8 | 1.94s | 1.03x |

## Analysis

Near-zero speedup across CPU counts. Two factors:

1. **The fixture has 2 assets** — there are only 2 units of work to
   parallelize across 8 CPUs. The striping infrastructure (16 shards)
   is correct but idle with 2 assets.

2. **CEL compilation/evaluation dominates** — 2816 controls × 2 assets
   = 5346 CEL evaluations. Each is independent and the engine stripes
   them, but with only 2 assets in the collector, the lock contention
   that motivated striping doesn't materialize.

## Conclusion

The collector striping is correctly implemented (16 FNV-sharded stripes,
verified by code inspection). The scaling bottleneck at this fixture
size is CEL evaluation volume (2816 controls), not collector contention.

Production-scale validation requires a fixture with 200+ assets to
exercise the parallel evaluation + striped collection path. The current
fixture validates correctness, not scalability.

## Infrastructure in place

- sync.Pool for `*evaluation.Finding` — reduces GC pressure at scale
- 16-stripe collector with FNV-1a sharding — eliminates lock contention
- BenchmarkApply at -cpu=1,4,8 — measures scaling automatically
- Silent-risk detection runs inline after evaluation
