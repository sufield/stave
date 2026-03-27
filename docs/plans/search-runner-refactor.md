# Plan: Refactor cmd/diagnose/docs/search.go

## Current State

The search runner is already well-structured:
- `search` method correctly delegates to `searchDocsFiles` (context-aware)
- Validation uses early returns with `UserError`
- Results are sliced to `MaxResults`

## Changes

### 1. Return SearchResult instead of writing

Change `Run` to return `(SearchResult, error)` so the runner is
pure logic. Move formatting to the Cobra RunE.

```go
// Before
func (r *SearchRunner) Run(ctx, req) error {
    // ...builds result...
    return r.report(res, req.Format)
}

// After
func (r *SearchRunner) Run(ctx, req) (SearchResult, error) {
    // ...builds result...
    return res, nil
}
```

### 2. Remove Stdout from SearchRunner

With formatting moved to the caller, `SearchRunner` no longer needs
an `io.Writer`. Remove `Stdout` field and `NewSearchRunner` constructor.

### 3. Move report to standalone function

`report` doesn't use the receiver. Convert to `writeSearchResult`
standalone function.

### 4. Remove Format from SearchRequest

Format is a presentation concern, not a search concern. Remove it
from `SearchRequest` and pass it directly to the writer.

### 5. Inline the search method

The `search` method is a one-line delegation to `searchDocsFiles`.
Inline it into `Run`.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/docs/search.go` | Return SearchResult, remove Stdout, standalone writer |

## Acceptance

- `Run` returns `(SearchResult, error)`
- `SearchRunner` has no `Stdout` field
- `Format` removed from `SearchRequest`
- `go test ./cmd/diagnose/docs/` passes
- `make script-test` passes
