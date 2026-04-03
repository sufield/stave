# Plan: CI Diff Runner — Null Safety and Report Extraction

Final cleanup for `cmd/enforce/cidiff/run.go`: guarantee non-nil
slices from the domain, extract report construction, and slim the
`Run` method to pure orchestration.

## Completed (prior commits)

| Item | Commit |
|------|--------|
| Context propagation through artifact loader | `a502f40` |
| `newRunner(cmd)` factory with quiet mode | `af77fbc` |

## Remaining Changes

### 1. Guarantee non-nil slices in CompareBaseline

**Problem**: `CompareBaseline` uses `var newFindings, resolvedFindings
[]BaselineEntry` which stays `nil` when no items are appended. cidiff
guards against this manually (lines 100-105), but baseline's
`ToReport` does not — a latent `"new": null` bug in JSON output.

**Change**: Initialize with empty slices in `CompareBaseline` so all
consumers get `[]` in JSON, then remove the nil guards from cidiff.

```go
// Before (evaluation/baseline.go:120)
var newFindings, resolvedFindings []BaselineEntry

// After
newFindings := make([]BaselineEntry, 0)
resolvedFindings := make([]BaselineEntry, 0)
```

This fixes both cidiff and baseline in one place.

Files changed:

| File | Change |
|------|--------|
| `internal/core/evaluation/baseline.go` | Init slices with `make` |
| `cmd/enforce/cidiff/run.go` | Remove nil guard block (lines 100-105) |

### 2. Extract `newDiffReport` helper

**Problem**: `Run` mixes orchestration (load, compare) with report
struct construction (15 lines of field mapping including sanitization
and summary derivation).

**Change**: Extract a `newDiffReport` method on Runner. Unlike
baseline's `ToReport` (which lives in the domain because
`BaselineComparison` is a domain type), `DiffReport` is a
cidiff-package type, so the helper stays in the package.

```go
func (r *Runner) newDiffReport(
    comparison evaluation.BaselineComparisonResult,
    currentPath string,
    baselinePath string,
    currentCount int,
    baselineCount int,
) DiffReport {
    return DiffReport{
        SchemaVersion:      kernel.SchemaCIDiff,
        Kind:               kernel.KindCIDiff,
        ComparedAt:         r.Clock.Now().UTC(),
        CurrentEvaluation:  sanitizePath(r.Sanitizer, currentPath),
        BaselineEvaluation: sanitizePath(r.Sanitizer, baselinePath),
        Summary: DiffSummary{
            BaselineFindings: baselineCount,
            CurrentFindings:  currentCount,
            NewFindings:      len(comparison.New),
            ResolvedFindings: len(comparison.Resolved),
        },
        New:      comparison.New,
        Resolved: comparison.Resolved,
    }
}
```

`Run` becomes:

```go
comparison := evaluation.CompareBaseline(baselineEntries, currentEntries)
report := r.newDiffReport(comparison, currentPath, baselinePath,
    len(currentEntries), len(baselineEntries))
```

### 3. Reuse single loader instance

**Problem**: `Run` calls `artifact.NewLoader()` twice — once per
evaluation file. This creates two loader instances where one suffices.

**Change**: Hoist to a local variable.

```go
// Before
currentEval, err := artifact.NewLoader().Evaluation(ctx, currentPath)
...
baselineEval, err := artifact.NewLoader().Evaluation(ctx, baselinePath)

// After
loader := artifact.NewLoader()
currentEval, err := loader.Evaluation(ctx, currentPath)
...
baselineEval, err := loader.Evaluation(ctx, baselinePath)
```

## No Change Needed

### Context propagation

`Run` already uses named `ctx` and passes it to both
`loader.Evaluation(ctx, ...)` calls.

### Error wrapping

All errors already wrapped with `%w` and descriptive context.

### sanitizePath helper

Small, focused, stays in `run.go`.

## Files Changed

| File | Change |
|------|--------|
| `internal/core/evaluation/baseline.go` | Init slices with `make` in `CompareBaseline` |
| `cmd/enforce/cidiff/run.go` | Extract `newDiffReport`, remove nil guards, reuse loader |

## Acceptance

- `CompareBaseline` always returns non-nil `New` and `Resolved` slices
- JSON output has `"new": []` not `"new": null` when no findings
- `Run` is orchestration only: load → compare → report → write → signal
- `go vet ./...` clean
- `make test` zero failures
