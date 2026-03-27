# Plan: Refactor cmd/diagnose/explain.go

## Problem

`composeFinder.FindByID` calls `f.newCtlRepo()` on every invocation,
re-initializing the repository (disk I/O, YAML parsing, schema
validation) each time. Currently `explain` calls it once, but the
pattern is fragile — any future bulk-explain or multi-control path
would pay the initialization cost repeatedly.

## Changes

### 1. Initialize repo in RunE, pass ready finder

Move `newCtlRepo()` from inside `composeFinder.FindByID` to the
RunE block. Pass the initialized repo to the finder.

```go
// Before (in composeFinder.FindByID — called per invocation)
repo, err := f.newCtlRepo()

// After (in RunE — called once)
repo, err := newCtlRepo()
finder := &repoFinder{repo: repo}
```

### 2. Simplify composeFinder to repoFinder

The finder becomes a thin wrapper around an already-initialized repo:

```go
type repoFinder struct {
    repo appcontracts.ControlRepository
}

func (f *repoFinder) FindByID(ctx context.Context, dir string, id kernel.ControlID) (policy.ControlDefinition, error) {
    controls, err := f.repo.LoadControls(ctx, dir)
    // ... find by ID ...
}
```

### 3. Remove factory from Explainer

`Explainer` takes the `ControlFinder` interface directly instead of
a factory. `NewExplainer` is no longer needed — construct inline.

### 4. Separate Run return from formatting

Change `Run` to return `(appexplain.ExplainResult, error)`. Move
formatting to the RunE block (consistent with open.go and search.go
refactors).

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/explain.go` | Init repo in RunE, repoFinder, return result |

## Acceptance

- `newCtlRepo()` called exactly once per command invocation
- No factory stored in Explainer or finder
- `Run` returns `(ExplainResult, error)`
- `go test ./...` zero failures
- `make script-test` passes
