# Plan: Executor First Run — Consolidate Duplicates and Guards

Remove the duplicated `fmt.Fprintf` block in `printNoProjectHintIfNeeded`
and combine guard clauses in `ensureFirstRunRunHint`.

## Changes

### 1. Consolidate duplicate Fprintf in printNoProjectHintIfNeeded

**Problem**: Lines 61 and 65 contain identical `fmt.Fprintf` calls —
one for the `err != nil` case, one for `!found`. The early return
on error means the hint is printed twice in separate branches.

**Change**: Combine into a single condition.

```go
// Before
if err != nil {
    fmt.Fprintf(a.Root.ErrOrStderr(), "No Stave project found...")
    return
}
if !found {
    fmt.Fprintf(a.Root.ErrOrStderr(), "No Stave project found...")
}

// After
if err != nil || !found {
    fmt.Fprintf(a.Root.ErrOrStderr(), "No Stave project found...")
}
```

### 2. Combine guard clauses in ensureFirstRunRunHint

**Problem**: Two separate early returns (`strings.Contains` then
`len(args) == 0`) when both result in returning the message
unchanged.

**Change**: Merge into a single guard.

```go
// Before
if strings.Contains(message, "\nRun:") {
    return message
}
if len(args) == 0 {
    return message
}

// After
if len(args) == 0 || strings.Contains(message, "\nRun:") {
    return message
}
```

Checking `len(args) == 0` first avoids the `strings.Contains` scan
when there are no args.

## No Change Needed

### Writer injection / HintService

Injecting `io.Writer` into `prepareFirstRunHint` or extracting a
`HintService` requires changing the `App` struct, `executor.go`,
and `main.go`. The current `os.Stderr` usage is documented as
intentional (runs before Cobra is ready). Defer to a separate
effort if test coverage for first-run hints becomes a priority.

### prepareFirstRunHint / markFirstRunHintSeenIfNeeded

Already clean — single responsibility, guard clauses, best-effort
marker write. No change.

## Files Changed

| File | Change |
|------|--------|
| `cmd/executor_firstrun.go` | Consolidate duplicate Fprintf, merge guard clauses |

## Acceptance

- `printNoProjectHintIfNeeded` has one Fprintf call, not two
- `ensureFirstRunRunHint` has one guard clause, not two
- `go vet ./cmd/...` clean
- `make test` zero failures
