---
status: done
---
# Plan: Refactor cmd/diagnose/prompt.go

## Status: Complete

## Changes Applied

### 1. Loop variable pointer — kept as `&controls[i]`

Go 1.22+ guarantees a fresh variable per loop iteration, so
`&controls[i]` is safe. The codebase requires Go 1.26 (per go.mod).
No change needed.

### 2. Use slices.MaxFunc for latest snapshot — done

Replaced 5-line manual iteration with `slices.MaxFunc`. Cleaner and
uses the standard library.

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

### 3. Eager JSON marshaling — kept as-is

Prompt is < 10KB typically. Deferring marshaling would propagate
type changes through `DiagnosticContext`, `PromptBuilder`, and
the adapter layer for negligible gain. Documented as future
optimization opportunity.

## Not Changed

- **`&controls[i]`**: Safe on Go 1.22+ (codebase requires Go 1.26)
- **buildPromptAdapter**: Already clean adapter pattern
- **DiagnosticContext wiring**: One caller, factory adds indirection
- **Streaming properties**: Prompt is small, not justified
