# Plan: Executor — Extract Error Handler from executeRootCommand

Separate error handling from command execution in
`executeRootCommand` for clarity.

## Changes

### 1. Extract handleExecutionError

**Problem**: `executeRootCommand` mixes command execution with
error logging, error presentation, and exit code resolution. At
18 lines, it's manageable but the "run command" and "handle failure"
concerns are interleaved.

**Change**: Extract the error-handling branch into
`handleExecutionError`.

```go
func (a *App) executeRootCommand(args []string) {
    if err := a.Root.Execute(); err != nil {
        a.handleExecutionError(err, args)
    }
}

func (a *App) handleExecutionError(err error, args []string) {
    exitCode := ExitCode(err)

    if a.Logger != nil {
        msg := err.Error()
        if idx := strings.Index(msg, "\n"); idx > 0 {
            msg = msg[:idx]
        }
        a.Logger.Debug("command failed", "error", msg, "exit_code", exitCode)
    }

    if !isSentinelError(err) {
        a.writeCommandError(err, args)
    }

    a.ExitFunc(exitCode)
}
```

`executeRootCommand` becomes a two-line function: execute, handle
error if any.

## No Change Needed

### signal.NotifyContext replacement

The current `installInterruptHandler` has specific behavior that
`signal.NotifyContext` doesn't provide: printing "Interrupted" to
stderr and handling the pre-bootstrap case where `a.cancel` is nil.
Replacing it would change observable behavior.

### HintService / PostExec / ErrOut

These require prior infrastructure (`HintService`, `ErrOut` field on
`App`, `PostExec` method) that doesn't exist. The current
`finalizeExecute` is already clean after the resolver injection
refactor.

### Context interrupt check

`a.Root.Context() != nil && a.Root.Context().Err() != nil` is
defensive (guards nil context) and correct. No simplification
without changing assumptions.

## Files Changed

| File | Change |
|------|--------|
| `cmd/executor.go` | Extract `handleExecutionError` from `executeRootCommand` |

## Acceptance

- `executeRootCommand` is two lines: execute + handle error
- `handleExecutionError` owns logging, presentation, and exit
- No behavior change
- `go vet ./cmd/...` clean
- `make test` zero failures
