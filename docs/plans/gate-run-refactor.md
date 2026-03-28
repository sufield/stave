# Plan: Gate Runner — Base Result, Sanitize Method, and Cleanup

Extract repeated result boilerplate into a helper, encapsulate
sanitization in a method, wrap bare errors, and reuse the artifact
loader.

## Changes

### 1. Add newBaseResult helper

**Problem**: All three policy functions repeat `SchemaVersion`,
`Kind`, and `CheckedAt` in their result literals. Adding a new
common field means editing three places.

**Change**: Add a helper that returns a `result` with boilerplate
fields populated.

```go
func newBaseResult(cfg config) result {
    return result{
        SchemaVersion: kernel.SchemaGate,
        Kind:          kernel.KindGateCheck,
        CheckedAt:     cfg.Clock.Now().UTC(),
    }
}
```

Each policy function starts with `res := newBaseResult(cfg)` and
sets only policy-specific fields.

### 2. Extract sanitize method on result

**Problem**: `Run` inlines four `cfg.Sanitizer.Path(...)` calls
with a nil guard. This is structural knowledge about `result` living
in the orchestration method.

**Change**: Add a `sanitize` method on `result`.

```go
func (res *result) sanitize(s kernel.Sanitizer) {
    res.EvaluationPath = s.Path(res.EvaluationPath)
    res.BaselinePath = s.Path(res.BaselinePath)
    res.ControlsPath = s.Path(res.ControlsPath)
    res.ObservationsPath = s.Path(res.ObservationsPath)
}
```

`Run` becomes:

```go
if cfg.Sanitizer != nil {
    res.sanitize(cfg.Sanitizer)
}
```

### 3. Wrap bare errors

Two bare error returns lack context:

| Location | Current | Wrapped |
|----------|---------|---------|
| `Run` (line 88) | `return err` | `return fmt.Errorf("gate execution: %w", err)` |
| `runPolicyOverdue` (line 161) | `return result{}, err` | `return result{}, fmt.Errorf("loading assets: %w", err)` |

### 4. Reuse single loader in runPolicyNew

**Problem**: `runPolicyNew` calls `artifact.NewLoader()` twice.

```go
// Before
eval, err := artifact.NewLoader().Evaluation(ctx, cfg.InPath)
...
base, err := artifact.NewLoader().Baseline(ctx, cfg.BaselinePath, ...)

// After
loader := artifact.NewLoader()
eval, err := loader.Evaluation(ctx, cfg.InPath)
...
base, err := loader.Baseline(ctx, cfg.BaselinePath, ...)
```

## No Change Needed

### Exporting types

`config`, `runner`, `result` are unexported and used only within
the gate package (including tests). Exporting them would change the
package API without a current consumer. Sibling packages (diff, fix)
also use unexported types for their internal structs. Keep as-is.

### Report function

Already clean — format dispatch with JSON/text/quiet paths. No
interface extraction needed for a single implementation.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/gate/run.go` | Add `newBaseResult`, `sanitize` method, wrap errors, reuse loader |

## Acceptance

- `SchemaVersion`/`Kind`/`CheckedAt` set in one place
- Sanitization encapsulated in `result.sanitize`
- All error returns wrapped with `%w`
- Single loader instance in `runPolicyNew`
- `go vet ./cmd/enforce/gate/...` clean
- `make test` zero failures
