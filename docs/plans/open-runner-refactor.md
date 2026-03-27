# Plan: Refactor cmd/diagnose/docs/open.go

## Problem

`OpenRunner.Run` mixes logic and presentation, and `summarizeAtMatch`
loads the entire file into memory just to read one line.

1. **Full file load for summary**: `summarizeAtMatch` calls
   `fsutil.ReadFileLimited` (reads entire file into `[]byte`), then
   `strings.Split` (allocates a `[]string` for every line). For a
   large markdown file this is O(file_size) memory for a single line.

2. **Logic + presentation coupled**: `Run` returns `error` and writes
   output internally via `r.write()`. This makes the runner hard to
   unit test — you can't inspect the result without parsing stdout.

3. **Context not threaded to summarize**: `summarizeAtMatch` does file
   I/O but doesn't accept `context.Context` for cancellation.

## Changes

### 1. Stream-based summarizeAtMatch

Replace `ReadFileLimited` + `strings.Split` with `bufio.Scanner` that
stops at the target line:

```go
func summarizeAtMatch(absPath string, targetLine int, fallback string) string {
    f, err := os.Open(absPath)
    if err != nil { return fallback }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    lineNo := 0
    for scanner.Scan() {
        lineNo++
        if lineNo < targetLine { continue }
        if lineNo >= targetLine+18 { break }
        if s := cleanLine(scanner.Text()); s != "" { return s }
    }
    return fallback
}
```

This reads only up to `targetLine + 18` lines, not the whole file.

### 2. Separate Run from output

Change `Run` to return `(OpenResult, error)` instead of `error`.
Move `write` call to the Cobra RunE:

```go
// Before
func (r *OpenRunner) Run(ctx, req) error {
    // ...builds result...
    return r.write(result, req.Format)
}

// After
func (r *OpenRunner) Run(ctx, req) (OpenResult, error) {
    // ...builds result...
    return result, nil
}

// In RunE:
result, err := runner.Run(cmd.Context(), req)
if err != nil { return err }
return writeOpenResult(cmd.OutOrStdout(), result, fmtValue)
```

### 3. Make cleanLine a package function

`cleanLine` doesn't use `r` (the receiver). Convert to standalone
function.

### 4. Remove fsutil import

After switching to scanner, `fsutil.ReadFileLimited` is no longer
needed in this file.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/docs/open.go` | Stream summary, return OpenResult, standalone cleanLine |

## What NOT to Change

- **Cobra command constructor**: Already thin and correct.
- **OpenResult struct**: Already well-defined with JSON tags.
- **resolveAbsPath**: Simple loop, no optimization needed.

## Acceptance

- `summarizeAtMatch` uses `bufio.Scanner`, not `ReadFileLimited`
- `Run` returns `(OpenResult, error)`
- `cleanLine` is a standalone function (no receiver)
- `fsutil` import removed from `open.go`
- `go test ./cmd/diagnose/docs/` passes
- `make script-test` passes
