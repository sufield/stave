# Plan: Executor Errors — Data-Driven Templates and Idiom Fixes

Replace the repeated switch cases in `errorInfoFromError` with a
data-driven template map, fix the `errors.As` idiom, and add a nil
guard.

## Changes

### 1. Replace switch with sentinel template map

**Problem**: `errorInfoFromError` repeats the same pattern four
times: check sentinel + exit code, build `ErrorInfo` with code,
title, and action. Adding a new sentinel category means adding
another case with the same structure.

**Change**: Define an `errorTemplate` struct and a
`sentinelTemplates` map keyed by exit code. The function looks up
the template and applies it.

```go
type errorTemplate struct {
    Code   ui.ErrorCode
    Title  string
    Action string
}

var sentinelTemplates = map[int]errorTemplate{
    ui.ExitSecurity: {
        Code:   ui.CodeSecurityAuditFindings,
        Title:  "Security audit gate failed",
        Action: "Review the generated security audit report and remediate findings at or above --fail-on.",
    },
    ui.ExitViolations: {
        Code:   ui.CodeViolationsFound,
        Title:  "Violations detected",
        Action: "Review findings and re-run `stave diagnose` for root-cause guidance.",
    },
    ui.ExitInputError: {
        Code:   ui.CodeInvalidInput,
        Title:  "Input validation failed",
        Action: "Run `stave validate` with the same inputs to get actionable fix hints.",
    },
}
```

The function becomes:

```go
if ui.IsSentinel(err) {
    if tmpl, ok := sentinelTemplates[ExitCode(err)]; ok {
        return ui.NewErrorInfo(tmpl.Code, message).
            WithTitle(tmpl.Title).
            WithAction(suggested + tmpl.Action).
            WithURL(docsRef)
    }
}
```

### 2. Fix errors.As idiom

**Problem**: `errors.As(err, new(*ui.UserError))` allocates a
throwaway pointer. The idiomatic Go pattern declares a typed
variable.

```go
// Before
case errors.As(err, new(*ui.UserError)):

// After
var userErr *ui.UserError
if errors.As(err, &userErr) {
```

### 3. Add nil guard to writeCommandError

**Problem**: If `err` is nil, `err.Error()` panics.

```go
func (a *App) writeCommandError(err error, args []string) {
    if err == nil {
        return
    }
    ...
}
```

## No Change Needed

### HintedError type / global registry

Moving error metadata into the error itself (`HintedError`) or a
global registry would require changing error return sites across
multiple packages. The template map in `executor_errors.go` captures
most of the benefit (centralized strings, single-point editing)
without the cross-cutting change.

### writeErrorInfo

Already has a nil guard and correct `os.Stderr` usage with fallback.

### isSentinelError

Thin wrapper — no change needed.

## Files Changed

| File | Change |
|------|--------|
| `cmd/executor_errors.go` | Template map, fix `errors.As`, nil guard |

## Acceptance

- Sentinel error classification uses map lookup, not repeated switch cases
- `errors.As` uses proper variable declaration
- `writeCommandError` guards against nil error
- Adding a new sentinel category requires one map entry
- `go vet ./cmd/...` clean
- `make test` zero failures
