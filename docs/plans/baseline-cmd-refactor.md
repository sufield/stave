# Plan: Baseline Command — Idiomatic Alignment

Align `cmd/enforce/baseline/` with the patterns established in `cidiff`
and the CLI command conventions in `CLAUDE.md`.

## Completed

### 1. Unified Runner Creation

`newCheckCmd` now uses the shared `newRunner(cmd)` helper, ensuring
`--force`, `--allow-symlink-out`, and quiet mode are respected
consistently across both `save` and `check`.

Commit: `51547f2` — Unify runner creation in baseline check subcommand.

## Remaining Changes

### 2. Add context.Context to Save and Check

**Problem**: `Save` and `Check` don't accept `context.Context`. The
sibling `cidiff.Runner.Run` already does — even though the parameter is
currently unused, accepting it allows CI timeouts and cancellation to
propagate when we later add cancellable I/O.

```go
// Before
func (r *Runner) Save(cfg SaveConfig) error {
func (r *Runner) Check(cfg CheckConfig) error {

// After
func (r *Runner) Save(ctx context.Context, cfg SaveConfig) error {
func (r *Runner) Check(ctx context.Context, cfg CheckConfig) error {
```

Call sites in `cmd.go` pass `cmd.Context()`:

```go
RunE: func(cmd *cobra.Command, _ []string) error {
    return newRunner(cmd).Save(cmd.Context(), cfg)
},
```

### 3. Wrap artifact loader errors

**Problem**: `Save` and `Check` return bare `err` from
`artifact.NewLoader().Evaluation()` and `.Baseline()`. The `cidiff`
runner wraps these with context (`"load current evaluation: %w"`),
which makes error messages actionable.

```go
// Before (run.go:55-57)
eval, err := artifact.NewLoader().Evaluation(inPath)
if err != nil {
    return err
}

// After
eval, err := artifact.NewLoader().Evaluation(inPath)
if err != nil {
    return fmt.Errorf("load evaluation %s: %w", inPath, err)
}
```

All three bare returns need wrapping:

| Method | Line | Wrap message |
|--------|------|-------------|
| `Save` | 56 | `"load evaluation %s: %w"` |
| `Check` | 89 | `"load evaluation %s: %w"` |
| `Check` | 95 | `"load baseline %s: %w"` |

## No Change Needed

### Clock injection

`NewRunner` already accepts `ports.Clock` interface — the constructor is
fully injectable. The CLI factory `newRunner` wires `ports.RealClock{}`
which is the correct pattern: CLI layer wires real dependencies, tests
call `NewRunner` directly with `ports.FixedClock`.

### Quiet mode / io.Discard

Passing `io.Discard` from the CLI layer when `--quiet` is set is a valid
pattern. The Runner doesn't need to know about quiet mode — it just
writes to its `io.Writer`.

### Naming consistency

Cobra generates `stave ci baseline [save|check]` correctly from the
parent chain. The `Long` help text already references the full path.
No naming issue.

### Early returns, flag binding

`RunE` functions are flat single-expression returns.
`MarkFlagRequired` is used for mandatory inputs. No change needed.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/baseline/run.go` | Add `ctx context.Context` param to `Save`/`Check`; wrap 3 bare loader errors |
| `cmd/enforce/baseline/cmd.go` | Pass `cmd.Context()` to `Save`/`Check` |

## Acceptance

- `Save` and `Check` accept `context.Context` as first parameter
- All artifact loader errors are wrapped with `%w` and include the file path
- Call sites pass `cmd.Context()`
- `go vet ./cmd/enforce/baseline/...` clean
- `make test` zero failures
