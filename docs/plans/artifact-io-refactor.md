# Plan: Refactor cmd/enforce/artifact/io.go

## Current State

29-line file, clean. `Loader` wraps `*evaljson.Loader` (concrete type).
Neither `Evaluation` nor `Baseline` validates input or takes context.

## Changes

### 1. Add input validation

```go
func (l *Loader) Evaluation(path string) (*safetyenvelope.Evaluation, error) {
    if path == "" {
        return nil, errors.New("evaluation path is required")
    }
    return l.adapter.LoadEnvelopeFromFile(path)
}

func (l *Loader) Baseline(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
    if path == "" {
        return nil, errors.New("baseline path is required")
    }
    return l.adapter.LoadBaselineFromFile(path, expectedKind)
}
```

### 2. Context propagation — deferred

Adding `context.Context` to `Evaluation` and `Baseline` requires
changing `evaljson.Loader` (the adapter), which would propagate to
all callers of `LoadEnvelopeFromFile` and `LoadBaselineFromFile`.
This is out of scope for this change. Documented as future work.

### 3. Interface extraction — deferred

Extracting an `envelopeLoader` interface for testability requires
callers to change how they construct the Loader. Only 4 callers
exist and all use `NewLoader()`. This is low-value until there's
a second adapter implementation.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/artifact/io.go` | Add path validation |

## Acceptance

- Empty path returns clear error instead of opaque adapter failure
- `go test ./...` zero failures
