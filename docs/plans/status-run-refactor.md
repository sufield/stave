# Plan: Status Runner — Report Helper and Error Context

Extract output formatting into a `report` helper and add path
context to error messages.

## Changes

### 1. Extract report helper

**Problem**: `Run` mixes orchestration (detect root, scan, enrich
session) with output formatting (JSON vs text dispatch). Extracting
a `report` helper keeps `Run` focused on the "what" and separates
the "how" of rendering.

```go
func (r *Runner) report(cfg config, res appstatus.Result) error {
    if cfg.Format.IsJSON() {
        return jsonutil.WriteIndented(cfg.Stdout, res)
    }
    if err := appstatus.FormatText(cfg.Stdout, res); err != nil {
        return fmt.Errorf("render status text: %w", err)
    }
    return nil
}
```

`Run` ends with `return r.report(cfg, result)`.

### 2. Add path context to error messages

Two errors lack the directory path for debugging:

| Current | Wrapped |
|---------|---------|
| `ui.WithNextCommand(err, "stave init")` | `ui.WithNextCommand(fmt.Errorf("project root not found in %s: %w", cfg.Dir, err), "stave init")` |
| `"scanning project: %w"` | `"scan project state at %s: %w", root` |

## No Change Needed

### Session loading

Already uses graceful degradation — checks error but doesn't
return it. Correct pattern.

### Runner/NewRunner

Already exported and correctly structured.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/status/run.go` | Extract `report` helper, add path context to errors |

## Acceptance

- `Run` ends with `r.report(cfg, result)`
- `FormatText` error wrapped with context
- `DetectProjectRoot` error includes directory path
- `go vet ./cmd/enforce/status/...` clean
- `make test` zero failures
