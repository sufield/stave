# Plan: Baseline Runner — Context-Aware I/O and Logic Extraction

Align `cmd/enforce/baseline/run.go` with Go best practices for
context propagation, error consistency, and domain encapsulation.

## Completed (prior commits)

| Item | Commit |
|------|--------|
| Unified `newRunner` for save and check | `51547f2` |
| `Save`/`Check` accept `context.Context` | `e193863` |
| Wrap bare artifact loader errors with `%w` | `e193863` |

## Remaining Changes

### 1. Propagate context through artifact.Loader (cross-cutting)

**Problem**: `Save` and `Check` accept `ctx` but discard it (`_`).
The artifact loader methods — `Evaluation(path)` and
`Baseline(path, kind)` — don't accept `context.Context`, so there is
nowhere to pass it. CI timeouts and SIGINT cancellation cannot
interrupt file reads.

**Scope**: This is a cross-cutting change. `artifact.Loader.Evaluation`
has 15+ call sites across 5 packages (baseline, cidiff, gate, report,
and cidiff tests). `artifact.Loader.Baseline` has 2 callers.

**Change** (4 layers deep):

```
Runner.Save/Check(ctx, ...)
  → artifact.Loader.Evaluation(ctx, path)          # cmd/enforce/artifact/io.go
    → evaljson.Loader.LoadEnvelopeFromFile(ctx, path) # internal/adapters/evaluation/loader.go
      → fsutil.ReadFileLimited(path)                  # unchanged (ctx deferred here)
```

Files changed:

| File | Change |
|------|--------|
| `cmd/enforce/artifact/io.go` | Add `ctx context.Context` to `Evaluation` and `Baseline` |
| `internal/adapters/evaluation/loader.go` | Add `ctx` to `LoadEnvelopeFromFile` and `LoadBaselineFromFile` |
| `cmd/enforce/baseline/run.go` | Use named `ctx` (remove `_`), pass to loader calls |
| `cmd/enforce/cidiff/run.go` | Pass `ctx` to loader calls |
| `cmd/enforce/gate/run.go` | Pass `ctx` to loader calls |
| `cmd/diagnose/report/cmd.go` | Pass `ctx` to loader call |
| `cmd/enforce/cidiff/cidiff_test.go` | Pass `context.Background()` to loader calls |

At the adapter layer, `ctx` is accepted but unused initially — the
same `_ context.Context` pattern cidiff already uses. This establishes
the contract so that a future change to context-aware file I/O
(e.g. `os.ReadFileContext` or select-on-cancel) requires no signature
changes upstream.

In `run.go`, the change is:

```go
// Before
func (r *Runner) Save(_ context.Context, cfg SaveConfig) error {
    ...
    eval, err := artifact.NewLoader().Evaluation(inPath)

// After
func (r *Runner) Save(ctx context.Context, cfg SaveConfig) error {
    ...
    eval, err := artifact.NewLoader().Evaluation(ctx, inPath)
```

### 2. Extract BaselineComparison construction into domain

**Problem**: `Check` manually populates a 15-line
`evaluation.BaselineComparison` struct from the
`BaselineComparisonResult`. This structural mapping is domain knowledge
(schema version, kind, summary derivation) living in the CLI runner.

**Change**: Add a `ToReport` method on `BaselineComparisonResult` in
`pkg/alpha/domain/evaluation/baseline.go`:

```go
// ToReport builds the serializable comparison report from the diff result.
func (r BaselineComparisonResult) ToReport(
    checkedAt time.Time,
    baselineFile string,
    evaluationFile string,
    baselineCount int,
    currentCount int,
) BaselineComparison {
    return BaselineComparison{
        SchemaVersion: kernel.SchemaBaseline,
        Kind:          kernel.KindBaselineCheck,
        CheckedAt:     checkedAt,
        BaselineFile:  baselineFile,
        Evaluation:    evaluationFile,
        Summary: BaselineComparisonSummary{
            BaselineFindings: baselineCount,
            CurrentFindings:  currentCount,
            NewFindings:      len(r.New),
            ResolvedFindings: len(r.Resolved),
        },
        New:      r.New,
        Resolved: r.Resolved,
    }
}
```

The runner call site becomes:

```go
// Before (run.go:101-116)
comparison := evaluation.CompareBaseline(base.Findings, current)
result := evaluation.BaselineComparison{
    SchemaVersion: kernel.SchemaBaseline,
    Kind:          kernel.KindBaselineCheck,
    CheckedAt:     r.Clock.Now().UTC(),
    BaselineFile:  baselinePath,
    Evaluation:    inPath,
    Summary: evaluation.BaselineComparisonSummary{
        BaselineFindings: len(base.Findings),
        CurrentFindings:  len(current),
        NewFindings:      len(comparison.New),
        ResolvedFindings: len(comparison.Resolved),
    },
    New:      comparison.New,
    Resolved: comparison.Resolved,
}

// After
comparison := evaluation.CompareBaseline(base.Findings, current)
result := comparison.ToReport(
    r.Clock.Now().UTC(), baselinePath, inPath,
    len(base.Findings), len(current),
)
```

Files changed:

| File | Change |
|------|--------|
| `pkg/alpha/domain/evaluation/baseline.go` | Add `ToReport` method on `BaselineComparisonResult` |
| `cmd/enforce/baseline/run.go` | Replace inline struct with `comparison.ToReport(...)` |

### 3. Normalize error wrap messages

**Problem**: Minor inconsistency in wrap message format.

| Current message | Issue |
|----------------|-------|
| `"create %s: %w"` | Missing noun — should be `"create baseline file"` |

The underlying `fileout.OpenOutputFile` already wraps with
`"creating file %q: %w"` and `"creating directory %q: %w"`, so the
runner's wrap adds the "what" context. Normalize to `verb + noun`:

```go
// Before
return fmt.Errorf("create %s: %w", outPath, err)

// After
return fmt.Errorf("create baseline file %s: %w", outPath, err)
```

Single line change in `Save`.

## Execution Order

1. **Step 2** (logic extraction) — self-contained, no cross-package impact
2. **Step 3** (error message) — single line
3. **Step 1** (context propagation) — cross-cutting, do last to batch
   all caller updates in one pass

## Files Changed (all steps)

| File | Step | Change |
|------|------|--------|
| `pkg/alpha/domain/evaluation/baseline.go` | 2 | Add `ToReport` method |
| `cmd/enforce/baseline/run.go` | 2,3 | Use `ToReport`, fix wrap message |
| `cmd/enforce/artifact/io.go` | 1 | Add `ctx` to `Evaluation`/`Baseline` |
| `internal/adapters/evaluation/loader.go` | 1 | Add `ctx` to `LoadEnvelopeFromFile`/`LoadBaselineFromFile` |
| `cmd/enforce/cidiff/run.go` | 1 | Pass `ctx` to loader |
| `cmd/enforce/gate/run.go` | 1 | Pass `ctx` to loader |
| `cmd/diagnose/report/cmd.go` | 1 | Pass `ctx` to loader |
| `cmd/enforce/cidiff/cidiff_test.go` | 1 | Pass `context.Background()` |

## Acceptance

- `BaselineComparisonResult.ToReport` produces identical JSON output
  (golden test: serialize before/after, byte-for-byte match)
- All artifact loader methods accept `context.Context` as first param
- `Save`/`Check` pass named `ctx` through to loader
- Error messages follow `"verb noun path: %w"` pattern
- `go vet ./...` clean
- `make test` zero failures
