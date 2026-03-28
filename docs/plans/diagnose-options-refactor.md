# Plan: Refactor cmd/diagnose/options.go

## Problem

`ToConfig` takes `*cobra.Command` and calls `cmd.Flags().Changed()`
three times, making it impossible to unit test without a full Cobra
command object. `resolveConfigDefaults` uses `cmdctx.EvaluatorFromCmd`
(service locator pattern).

## Changes

### 1. Capture "changed" state in the options struct

Add boolean fields to `diagnoseOptions` that record whether flags
were explicitly set. Populate them in `Prepare` (which already has
access to `cmd`).

```go
type diagnoseOptions struct {
    // ... existing fields ...
    controlsSet bool
    obsSet      bool
    formatSet   bool
}

func (o *diagnoseOptions) Prepare(cmd *cobra.Command) error {
    o.controlsSet = cmd.Flags().Changed("controls")
    o.obsSet = cmd.Flags().Changed("observations")
    o.formatSet = cmd.Flags().Changed("format")
    o.resolveConfigDefaults(cmd)
    return nil
}
```

### 2. Remove `*cobra.Command` from `ToConfig`

`ToConfig` reads `o.controlsSet` etc. instead of calling
`cmd.Flags().Changed()`. It takes `cliflags.GlobalFlags` and
`compose.IOWriters` (stdout/stderr/stdin) instead of `cmd`.

```go
// Before
func (o *diagnoseOptions) ToConfig(cmd *cobra.Command) (Config, error)

// After
func (o *diagnoseOptions) ToConfig(flags cliflags.GlobalFlags, w compose.IOWriters) (Config, error)
```

### 3. Update the RunE caller

```go
// Before
RunE: func(cmd *cobra.Command, _ []string) error {
    cfg, err := opts.ToConfig(cmd)

// After
RunE: func(cmd *cobra.Command, _ []string) error {
    flags := cliflags.GetGlobalFlags(cmd)
    writers := compose.IOWriters{
        Stdout: cmd.OutOrStdout(),
        Stderr: cmd.ErrOrStderr(),
        Stdin:  cmd.InOrStdin(),
    }
    cfg, err := opts.ToConfig(flags, writers)
```

### 4. Keep resolveConfigDefaults as-is

It needs `cmd` to access `cmdctx.EvaluatorFromCmd`. This is
acceptable because it runs in `Prepare` (the CLI layer), not in
`ToConfig` (which becomes testable). The service locator concern
is contained to one place.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/options.go` | Add changed booleans, remove cmd from ToConfig |
| `cmd/diagnose/commands.go` | Update RunE to pass flags + writers |

## What NOT to Change

- **`resolveConfigDefaults`**: Still needs `cmd` for evaluator access.
  The Cobra coupling is contained to `Prepare`.
- **Completion logic**: Already correct with `cliflags.CompleteFixed`.
- **`BindFlags`**: Already clean.

## Acceptance

- `ToConfig` does not take `*cobra.Command`
- `cmd.Flags().Changed()` only called in `Prepare`
- `go test ./...` zero failures
- `make script-test` passes
