# Plan: Diff Runner — Deferred Progress Cleanup

Use `defer stop()` for the progress spinner to ensure cleanup on
panic or early error, matching the idiomatic Go resource cleanup
pattern.

## Changes

### 1. Defer progress stop with explicit pre-render call

**Problem**: `stop()` is called manually after `computeDelta`. If
`computeDelta` panics (e.g. nil map in snapshot comparison), the
spinner keeps running and corrupts stderr.

**Change**: Add `defer stop()` for safety, then call `stop()`
explicitly before rendering output so the spinner clears before
results appear.

```go
// Before
stop := progress.BeginProgress("Computing observation delta")
delta, err := r.computeDelta(ctx, cfg.ObservationsDir, cfg.Filter)
stop()
if err != nil {
    return err
}

// After
stop := progress.BeginProgress("Computing observation delta")
defer stop()

delta, err := r.computeDelta(ctx, cfg.ObservationsDir, cfg.Filter)
if err != nil {
    return err
}

stop()
```

Calling `stop()` twice is safe — progress stop functions are
idempotent.

## No Change Needed

### LoadSnapshots performance

Snapshot loading and "latest two" selection happen in the adapter
layer. `LoadSnapshots` already accepts `ctx` for cancellation.
`asset.LatestTwoSnapshots` is a pure function (sort + slice).
These are out of scope for `run.go`.

### ApplyFilter allocation

`ApplyFilter` returns a new `ObservationDelta`. For the snapshot
diff use case (comparing two snapshots), the change list is bounded
by the number of assets — not a scaling concern. Out of scope.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/diff/run.go` | Add `defer stop()`, move explicit `stop()` before output |

## Acceptance

- Progress spinner stops on panic, error, or success
- Spinner clears before output rendering begins
- `go vet ./cmd/enforce/diff/...` clean
- `make test` zero failures
