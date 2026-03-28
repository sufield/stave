# Plan: Refactor cmd/diagnose/prompt.go

## Problem

Three issues:

1. **Pointer to loop variable**: `loadControlsMap` takes `&controls[i]`
   which is safe in Go 1.22+ (loop var per iteration) but the codebase
   targets Go 1.21+. Use explicit local copy for clarity and safety.

2. **Manual max search**: `loadAssetProperties` manually iterates to
   find the latest snapshot. Use `slices.MaxFunc` for readability.

3. **Eager JSON marshaling**: `loadAssetProperties` marshals asset
   properties to `string` immediately via `json.MarshalIndent`. This
   allocates a large string that's just embedded in the prompt later.
   Defer marshaling until output time.

## Changes

### 1. Fix loop variable pointer in loadControlsMap

```go
// Before
for i := range controls {
    ctlByID[controls[i].ID] = &controls[i]
}

// After
for i := range controls {
    ctl := controls[i]
    ctlByID[ctl.ID] = &ctl
}
```

### 2. Use slices.MaxFunc for latest snapshot

```go
// Before
latest := snapshots[0]
for _, s := range snapshots[1:] {
    if s.CapturedAt.After(latest.CapturedAt) {
        latest = s
    }
}

// After
latest := slices.MaxFunc(snapshots, func(a, b asset.Snapshot) int {
    return a.CapturedAt.Compare(b.CapturedAt)
})
```

### 3. Return raw properties instead of marshaled string

Change `loadAssetProperties` to return `map[string]any` (the raw
properties) instead of a pre-marshaled JSON string. The prompt
builder marshals at render time.

This requires checking if `DiagnosticContext.AssetPropsJSON` can
accept raw data instead of a string. If the app layer and adapter
both expect a string, keep the marshaling but document the tradeoff.

**Decision**: Check the downstream consumers. If changing the type
propagates through too many files, keep the string but note the
optimization opportunity.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/prompt.go` | Fix loop var, slices.MaxFunc |

## What NOT to Change

- **buildPromptAdapter**: Already a clean adapter pattern.
- **DiagnosticContext wiring**: The RunE is already reasonably thin.
  Moving to a factory adds indirection for one caller.
- **Streaming properties**: The prompt is small (< 10KB typically).
  Streaming adds complexity for negligible gain.

## Acceptance

- Loop variable pointer uses local copy
- `slices.MaxFunc` replaces manual iteration
- `go test ./...` zero failures
- `make script-test` passes
