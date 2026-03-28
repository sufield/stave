# Plan: Refactor cmd/enforce/artifact/baseline.go

## Current State

The file is already well-structured (36 lines). Key finding:
`SanitizeBaselineEntries` already returns a new slice — the
copy-on-write concern from the review is already handled.

## Changes

### 1. Nil-guard the sanitizer call

Currently `SanitizeBaselineEntries` handles `nil` sanitizer internally.
But the call site should be explicit about intent:

```go
// Before
current = output.SanitizeBaselineEntries(san, current)

// After
if san != nil {
    current = output.SanitizeBaselineEntries(san, current)
}
```

### 2. Add HasNewViolations helper

```go
func (r BaselineComparisonResult) HasNewViolations() bool {
    return len(r.Comparison.New) > 0
}
```

This keeps the "Is it broken?" question close to the data.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/artifact/baseline.go` | Nil guard, HasNewViolations helper |

## What NOT to Change

- **SanitizeBaselineEntries**: Already returns a new slice (copy-on-write).
  No mutation safety issue.
- **CompareBaseline**: Pure domain function, already correct.

## Acceptance

- Sanitizer nil-guarded at call site
- `HasNewViolations()` method available on result
- `go test ./...` zero failures
