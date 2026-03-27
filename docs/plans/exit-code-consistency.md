# Plan: Fix Exit Code Consistency

## Problem

Two confirmed issues with exit code handling:

### Issue 1: Input errors exit 4 instead of 2

Validation errors in `cmd/apply/options.go` lines 141, 145, 150, 155
return plain `fmt.Errorf` or unwrapped errors. These fall through to
the default case in `ExitCode()` and get exit 4 (internal error)
instead of exit 2 (input error).

The documented contract (root_help.go, all command Long descriptions)
says exit 2 = input error. But these input validation failures
silently return exit 4.

**Affected code:**
```
options.go:141  ParseProfile() error         → exit 4 (should be 2)
options.go:145  "--input is required" error   → exit 4 (should be 2)
options.go:150  ResolveClock() error          → exit 4 (should be 2)
options.go:155  ResolveFormatValuePure() error → exit 4 (should be 2)
```

**Working correctly:**
```
options.go:222  parseDomainOptions() wraps as &ui.UserError → exit 2 ✓
```

### Issue 2: UserError not in IsSentinel, causing envelope mismatch

`executor_errors.go` classifies errors for the error envelope. It checks
`IsSentinel(err)` first, then `UserError` separately. But `IsSentinel`
doesn't include `UserError`. This means a `UserError` gets:
- Exit code: 2 (correct, from `ExitCode()`)
- Error envelope: potentially `INTERNAL_ERROR` if the error also
  doesn't match the `errors.As(err, new(*ui.UserError))` check

The fix in `executor_errors.go:41` does catch `UserError` separately
with `errors.As`, mapping it to `CodeInvalidInput`. So the envelope
IS correct for direct `UserError` wrapping. But if `UserError` is
nested inside another error wrapper, the `errors.As` may not reach it.

## Changes

### Fix 1: Wrap validation errors as UserError

In `cmd/apply/options.go`, wrap the 4 plain validation errors:

```go
// Before
return RunConfig{}, fmt.Errorf("--input is required when using --profile %s", o.Profile)

// After
return RunConfig{}, &ui.UserError{Err: fmt.Errorf("--input is required when using --profile %s", o.Profile)}
```

Apply to all 4 locations (lines 141, 145, 150, 155).

Also check other command options files for the same pattern:
- `cmd/enforce/gate/options.go`
- `cmd/enforce/diff/options.go`
- `cmd/prune/upcoming/cmd.go`

### Fix 2: Audit all resolveProfileMode errors

Every error returned from `resolveProfileMode` represents a user
input problem (bad profile name, missing --input flag, invalid --now,
invalid --format). All should exit 2.

## Files Changed

| File | Change |
|------|--------|
| `cmd/apply/options.go` | Wrap 4 validation errors as `&ui.UserError{}` |

## What NOT to Change

- **IsSentinel function**: Adding `UserError` to `IsSentinel` would
  change semantics — sentinel errors are specific well-known conditions,
  not a general category. `UserError` is correctly a type, not a sentinel.
- **executor_errors.go**: The `errors.As(err, new(*ui.UserError))` check
  at line 41 already handles `UserError` correctly for the envelope.
- **ExitCode function**: Already correct — checks `errors.As` for
  `UserError`.

## Already Fixed (from audit)

- Issue 3 (comment drift): Comment is accurate, no fix needed
- Issue 4 (architecture docs): Command Map is current, no stale paths
- Issue 5 (test comment): Already says "apply", not "evaluate"

## Acceptance

- All validation errors in `resolveProfileMode` return exit 2
- `stave apply --profile aws-s3` with missing `--input` exits 2 (not 4)
- `stave apply --profile aws-s3 --input x --now bad` exits 2 (not 4)
- `go test ./...` zero failures
- `make script-test` passes
