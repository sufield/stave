# Plan: Diff Output — Buffered Writer and Early Exit

Performance and correctness refinements for `renderText` in
`cmd/enforce/diff/output.go`.

## Changes

### 1. Buffer writes with bufio.NewWriter

**Problem**: `renderText` calls `fmt.Fprintf(w, ...)` for every
change and every property diff. For a delta with thousands of changes,
each `Fprintf` is a separate syscall when `w` is an `*os.File`.

**Change**: Wrap `w` in `bufio.NewWriter` and flush at the end.

```go
// Before
func renderText(w io.Writer, out asset.ObservationDelta) error {
    var firstErr error
    printf := func(format string, args ...any) {
        ...
        _, firstErr = fmt.Fprintf(w, format, args...)
    }

// After
func renderText(w io.Writer, out asset.ObservationDelta) error {
    bw := bufio.NewWriter(w)
    defer bw.Flush()

    var firstErr error
    printf := func(format string, args ...any) {
        ...
        _, firstErr = fmt.Fprintf(bw, format, args...)
    }
```

`defer bw.Flush()` ensures the buffer is flushed even on early
returns. The flush error is not separately checked because
`firstErr` already captures any write failure from the underlying
writer.

### 2. Early exit in change iteration loop

**Problem**: After a write error, the outer `for` loop continues
iterating all remaining changes and property diffs, calling `printf`
which short-circuits but still pays the loop overhead.

**Change**: Break from the outer loop on error.

```go
// Before
for _, c := range out.Changes {
    printf("- %s [%s]\n", c.AssetID, c.ChangeType)
    for _, p := range c.PropertyChanges {
        printf("  * %s: %v -> %v\n", p.Path, p.From, p.To)
    }
}

// After
for _, c := range out.Changes {
    if firstErr != nil {
        break
    }
    printf("- %s [%s]\n", c.AssetID, c.ChangeType)
    for _, p := range c.PropertyChanges {
        printf("  * %s: %v -> %v\n", p.Path, p.From, p.To)
    }
}
```

## No Change Needed

### %v formatting for PropertyChange.From/To

`From` and `To` are `any` typed — they can be strings, numbers, bools,
or nested maps. `%v` is the correct verb since the concrete type varies.
Sanitization is applied upstream in `runner.Run` before `renderText`
is called. No change.

### writeOutput dispatch

Already clean: quiet guard, format dispatch, delegation to
`renderText` or `jsonutil.WriteIndented`. No change.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/diff/output.go` | Add `bufio.NewWriter`, early exit in loop |

## Acceptance

- `renderText` uses buffered writer
- Loop exits early on first write error
- `go vet ./cmd/enforce/diff/...` clean
- `make test` zero failures
