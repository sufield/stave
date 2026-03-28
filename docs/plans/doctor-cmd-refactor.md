# Plan: Refactor cmd/doctor/cmd.go

## Problem

Two issues:

1. **Environmental discovery in runner**: `Run` calls `os.Getwd()` and
   `os.Executable()` when `Cwd` or `BinaryPath` are empty. These
   should be resolved at the CLI boundary so the runner is deterministic
   and testable.

2. **Quiet branching inside Run**: The `if cfg.Quiet` block short-circuits
   before reporting. Better to pass `io.Discard` as `Stdout` so the
   runner stays linear.

## Changes

### 1. Resolve Cwd and BinaryPath in RunE

Move `os.Getwd()` and `os.Executable()` to the RunE block. The config
always has values populated — runner never calls the OS.

```go
// Before (in runner.Run)
if cfg.Cwd == "" {
    cwd, err := os.Getwd()

// After (in RunE)
cwd, err := os.Getwd()
if err != nil { return err }
exe, err := os.Executable()
if err != nil { return err }
return newRunner().Run(config{
    Cwd:        cwd,
    BinaryPath: exe,
    // ...
})
```

### 2. Use io.Discard for quiet mode

Pass `io.Discard` as `Stdout` when quiet is set. Remove the
quiet-mode branch from `Run`.

```go
// Before (in RunE)
Quiet:  cliflags.GetGlobalFlags(cmd).Quiet,
Stdout: cmd.OutOrStdout(),

// After (in RunE)
stdout := cmd.OutOrStdout()
if cliflags.GetGlobalFlags(cmd).Quiet {
    stdout = io.Discard
}
// ...
Stdout: stdout,
```

### 3. Remove Quiet from config

With quiet handled via `io.Discard`, the `Quiet` field is no longer
needed on the config struct.

### 4. Inject version into newRunner

```go
// Before
func newRunner() *runner {
    return &runner{Version: staveversion.String}
}

// After
func newRunner(version string) *runner {
    return &runner{Version: version}
}
```

## Files Changed

| File | Change |
|------|--------|
| `cmd/doctor/cmd.go` | Resolve env in RunE, io.Discard for quiet, inject version |

## Acceptance

- `runner.Run` does not call `os.Getwd()` or `os.Executable()`
- `config` has no `Quiet` field
- `newRunner` takes `version string`
- `go test ./...` zero failures
- `make script-test` passes
