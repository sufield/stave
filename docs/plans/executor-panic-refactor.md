# Plan: Executor Panic Recovery — Stack Trace and Separation

Capture `debug.Stack()` for debuggability, always log the full
trace, and separate logging from message formatting.

## Changes

### 1. Capture and log stack trace

**Problem**: `recoverExecutePanic` logs the panic value but not the
stack trace. Without `debug.Stack()`, developers know *what* crashed
but not *where*.

**Change**: Call `debug.Stack()` immediately after recovery and
always log it alongside the panic value.

```go
func (a *App) recoverExecutePanic() {
    if recovered := recover(); recovered != nil {
        stack := debug.Stack()

        panicMsg := panicMessageFromValue(recovered)
        sanitized := a.sanitizeExecuteMessage(panicMsg)

        if a.Logger != nil {
            a.Logger.Error("panic recovered",
                "panic", sanitized,
                "stack", string(stack),
            )
        }
        ...
    }
}
```

Logging moves out of `panicUserMessage` into `recoverExecutePanic`
so the trace is always captured regardless of verbosity.

### 2. Extract buildPanicErrorInfo helper

**Problem**: `recoverExecutePanic` mixes logging, message formatting,
ErrorInfo construction, and edition-based action selection.

**Change**: Extract a `buildPanicErrorInfo` method that takes the
sanitized message and returns `*ui.ErrorInfo`.

```go
func (a *App) buildPanicErrorInfo(sanitized string) *ui.ErrorInfo {
    userMsg := "internal error occurred; rerun with -vv to see details"
    if a.Flags.Verbosity >= 2 {
        userMsg = fmt.Sprintf("internal error: %s", sanitized)
    }

    action := "Rerun with -vv, then run `stave-dev doctor` or contact support if this error persists."
    if a.Edition == EditionDev {
        action = "Rerun with -vv, then run `stave bug-report` and attach the bundle if it persists."
    }

    return ui.NewErrorInfo(ui.CodeInternalError, userMsg).
        WithTitle("Internal error").
        WithAction(action).
        WithURL(metadata.IssuesRef())
}
```

### 3. Remove panicUserMessage

Absorbed into `buildPanicErrorInfo`. The logging side effect that
was inside `panicUserMessage` moves to the caller. No separate
method needed.

The resulting `recoverExecutePanic` is a clean four-step flow:
capture → log → build UI → exit.

## No Change Needed

### panicMessageFromValue

Already clean with type switch for `error`, `string`, and default.

### sanitizeExecuteMessage

Thin wrapper, stays as-is.

## Files Changed

| File | Change |
|------|--------|
| `cmd/executor_panic.go` | Add `debug.Stack()`, extract `buildPanicErrorInfo`, remove `panicUserMessage` |

## Acceptance

- Stack trace captured via `debug.Stack()` on every panic
- Stack always logged regardless of verbosity level
- `recoverExecutePanic` is four steps: capture, log, build info, exit
- `go vet ./cmd/...` clean
- `make test` zero failures
