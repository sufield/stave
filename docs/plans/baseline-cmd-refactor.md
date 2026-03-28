# Plan: Refactor cmd/enforce/baseline/cmd.go

## Problem

`newCheckCmd` manually constructs `NewRunner` with different parameters
than `newSaveCmd` uses via the `newRunner` helper — empty `FileOptions`,
no quiet-mode handling, no `--force`/`--allow-symlink-out` respect.

## Changes

### 1. Use `newRunner` for both subcommands

`newCheckCmd` currently bypasses the shared `newRunner` helper:

```go
// Before (check)
RunE: func(cmd *cobra.Command, _ []string) error {
    return NewRunner(
        ports.RealClock{},
        cliflags.GetGlobalFlags(cmd).GetSanitizer(),
        fileout.FileOptions{},       // empty — misses Force/AllowSymlinks
        cmd.OutOrStdout(),            // misses quiet handling
    ).Check(cfg)
},

// After (check — uses shared helper)
RunE: func(cmd *cobra.Command, _ []string) error {
    return newRunner(cmd).Check(cfg)
},
```

This ensures `--force`, `--allow-symlink-out`, and quiet mode are
respected consistently.

### 2. No other changes needed

- **Clock injection**: `newRunner` already injects `ports.RealClock{}`.
  For tests, `NewRunner` accepts `ports.Clock` interface — tests can
  pass a mock directly. No change needed.
- **Context**: Adding `ctx` to `Save`/`Check` would propagate to
  the runner methods which don't do cancellable I/O currently. Defer.
- **Naming**: Cobra generates `stave ci baseline check` correctly
  from the parent chain. No naming issue.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/baseline/cmd.go` | `newCheckCmd` uses `newRunner(cmd)` |

## Acceptance

- Both `save` and `check` use the same `newRunner` helper
- `--force` and `--allow-symlink-out` respected in `check`
- Quiet mode works for `check`
- `go test ./...` zero failures
