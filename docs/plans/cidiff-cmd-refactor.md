# Plan: CI Diff Command — Dependency Consistency and Flag Resolution

Align `cmd/enforce/cidiff/cmd.go` with the factory and validation
patterns established in `baseline` and the CLI command conventions
in `CLAUDE.md`.

## Completed (prior commits)

| Item | Commit |
|------|--------|
| Context propagation through artifact loader | `a502f40` |
| Error wrapping on all loader calls | `e193863` |

## Remaining Changes

### 1. Extract `newRunner(cmd)` factory

**Problem**: `RunE` manually constructs `NewRunner` inline with
`ports.RealClock{}`, `gf.GetSanitizer()`, and `cmd.OutOrStdout()`.
If global flags like `--quiet` need to be respected, every command
must duplicate the same wiring logic.

**Change**: Extract a package-level `newRunner(cmd)` helper matching
the `baseline` pattern. Include quiet mode handling so `--quiet`
suppresses JSON output (exit-code-only mode).

```go
// Before (cmd.go RunE)
RunE: func(cmd *cobra.Command, _ []string) error {
    gf := cliflags.GetGlobalFlags(cmd)
    runner := NewRunner(
        ports.RealClock{},
        gf.GetSanitizer(),
        cmd.OutOrStdout(),
    )
    return runner.Run(cmd.Context(), cfg)
},

// After (cmd.go)
func newRunner(cmd *cobra.Command) *Runner {
    gf := cliflags.GetGlobalFlags(cmd)
    stdout := cmd.OutOrStdout()
    if !gf.TextOutputEnabled() {
        stdout = io.Discard
    }
    return NewRunner(
        ports.RealClock{},
        gf.GetSanitizer(),
        stdout,
    )
}

RunE: func(cmd *cobra.Command, _ []string) error {
    return newRunner(cmd).Run(cmd.Context(), cfg)
},
```

Imports added to `cmd.go`: `io`,
`github.com/sufield/stave/internal/platform/fileout` removed (not needed),
`github.com/sufield/stave/pkg/alpha/domain/ports` already present.

### 2. Same-file validation — NOT ADDED

Same-file comparison (`--current X --baseline X`) is a valid use case
for verifying "no drift" with a single evaluation file. The existing
`ci_workflow.txtar` integration test exercises this pattern. No
`PreRunE` validation added.

## No Change Needed

### Context propagation

`Run` already accepts named `ctx` and passes it to both
`artifact.NewLoader().Evaluation(ctx, ...)` calls.

### Error wrapping

All loader errors are already wrapped with `%w` and include
descriptive context (`"load current evaluation"`,
`"load baseline evaluation"`).

### Flag binding

`MarkFlagRequired` is used for `--current` and `--baseline`. No
change needed.

### SilenceUsage / SilenceErrors

Both already set to `true`.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/cidiff/cmd.go` | Extract `newRunner(cmd)`, add `PreRunE` same-file check, slim `RunE` |

## Acceptance

- `newRunner(cmd)` constructs the runner with clock, sanitizer, and
  quiet-aware stdout
- `RunE` is a single-expression return
- Same-file comparison still works (validated by ci_workflow.txtar)
- `--quiet` suppresses JSON output (exit code only)
- `go vet ./cmd/enforce/cidiff/...` clean
- `make test` zero failures
