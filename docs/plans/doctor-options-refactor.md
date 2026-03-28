# Plan: Refactor cmd/doctor/options.go

## Problem

`resolveFormat` takes `*cobra.Command` to call `compose.ResolveFormatValue(cmd, ...)`.
A pure alternative `ResolveFormatValuePure` already exists that takes
a `formatChanged bool` instead of `cmd`. Capturing the changed state
in `Prepare` decouples format resolution from Cobra.

## Changes

### 1. Capture formatChanged in Prepare

```go
type options struct {
    Format        string
    formatChanged bool  // NEW
}

func (o *options) Prepare(cmd *cobra.Command) error {
    o.formatChanged = cmd.Flags().Changed("format")
    return nil
}
```

### 2. Use ResolveFormatValuePure in resolveFormat

```go
// Before
func (o *options) resolveFormat(cmd *cobra.Command) (ui.OutputFormat, error) {
    return compose.ResolveFormatValue(cmd, o.Format)
}

// After
func (o *options) resolveFormat() (ui.OutputFormat, error) {
    return compose.ResolveFormatValuePure(o.Format, o.formatChanged, false)
}
```

### 3. Update RunE caller

```go
// Before
fmtValue, err := opts.resolveFormat(cmd)

// After
fmtValue, err := opts.resolveFormat()
```

## Files Changed

| File | Change |
|------|--------|
| `cmd/doctor/options.go` | Capture formatChanged, use Pure variant |
| `cmd/doctor/cmd.go` | Update resolveFormat call (no cmd arg) |

## Acceptance

- `resolveFormat` does not take `*cobra.Command`
- `cmd.Flags().Changed` only called in `Prepare`
- `go test ./...` zero failures
