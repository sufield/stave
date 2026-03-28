# Plan: Generate Runner — Export Types, Safe Close, Constructor

Export internal types for testability, capture `file.Close()` error,
and add a `NewRunner` constructor for consistency.

## Changes

### 1. Export result and plan types

**Problem**: `result` and `plan` are unexported, preventing
integration tests from inspecting generation outcomes without
calling the full `Run` method.

**Change**: Rename `result` → `Result`, `plan` → `Plan`, and
export `Plan` fields.

```go
// Before
type result struct { ... }
type plan struct {
    result   result
    rendered string
}

// After
type Result struct { ... }
type Plan struct {
    Result   Result
    Rendered string
}
```

All internal references updated (`buildPlan` → `BuildPlan`,
`writeDryRun`/`writeResult` accept `Result`).

### 2. Add NewRunner constructor

**Problem**: `Runner` is constructed via struct literal in `cmd.go`.
Other packages use `NewRunner` constructors for consistency.

**Change**: Add a simple constructor.

```go
func NewRunner(opts fileout.FileOptions) *Runner {
    return &Runner{FileOptions: opts}
}
```

Update `cmd.go` to use `NewRunner(fileout.FileOptions{...})`.

### 3. Capture file.Close error in writeOutputFile

**Problem**: `defer file.Close()` discards the close error. On a
full disk, `WriteString` succeeds (buffered) but `Close` fails,
causing silent data loss.

**Change**: Use named return with deferred close capture.

```go
// Before
func (r *Runner) writeOutputFile(outPath, rendered string) error {
    file, err := fileout.OpenOutputFile(outPath, r.FileOptions)
    if err != nil {
        return err
    }
    defer file.Close()
    ...
}

// After
func (r *Runner) writeOutputFile(outPath, rendered string) (err error) {
    file, err := fileout.OpenOutputFile(outPath, r.FileOptions)
    if err != nil {
        return fmt.Errorf("open output file %s: %w", outPath, err)
    }
    defer func() {
        if closeErr := file.Close(); closeErr != nil && err == nil {
            err = closeErr
        }
    }()
    ...
}
```

## No Change Needed

### validateInputPath, loadFindingRefs, buildOutput

Already well-structured with descriptive error wrapping and clear
separation. No changes.

### Mode/ParseMode

Already correct with `ui.EnumError` and `ui.NormalizeToken`.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/generate/run.go` | Export `Result`/`Plan`/`BuildPlan`, add `NewRunner`, safe close |
| `cmd/enforce/generate/cmd.go` | Use `NewRunner` instead of struct literal |

## Acceptance

- `Result` and `Plan` are exported types
- `BuildPlan` is exported for side-effect-free testing
- `NewRunner` constructor used in `cmd.go`
- `file.Close()` error captured via named return
- `go vet ./cmd/enforce/generate/...` clean
- `make test` zero failures
