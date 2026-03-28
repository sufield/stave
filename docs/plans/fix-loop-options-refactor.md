# Plan: Fix Loop Options — Testable Defaults and OutDir Validation

Decouple `resolveConfigDefaults` from `*cobra.Command` for unit
testing and add fail-fast OutDir validation before the expensive
fix-loop begins.

## Completed (prior commit)

| Item | Commit |
|------|--------|
| `ToRequest(cmd)` method on loopOptions | `943dd3a` |

## Changes

### 1. Interface-based config defaults

**Problem**: `resolveConfigDefaults` takes `*cobra.Command` to access
the project config evaluator and flag-changed state. This makes it
impossible to unit test default resolution without constructing a full
Cobra command tree with injected context.

**Change**: Define a `configDefaults` interface with the two methods
used, and have `resolveConfigDefaults` accept the interface plus
`*pflag.FlagSet`.

```go
// configDefaults provides project-level defaults for loop options.
type configDefaults interface {
    MaxUnsafeDuration() string
    AllowUnknownInput() bool
}

// Before
func (o *loopOptions) resolveConfigDefaults(cmd *cobra.Command) {
    eval := cmdctx.EvaluatorFromCmd(cmd)
    if !cmd.Flags().Changed("max-unsafe") {
        o.MaxUnsafeRaw = eval.MaxUnsafeDuration()
    }
    ...
}

// After
func (o *loopOptions) resolveConfigDefaults(defaults configDefaults, flags *pflag.FlagSet) {
    if defaults == nil {
        return
    }
    if !flags.Changed("max-unsafe") {
        o.MaxUnsafeRaw = defaults.MaxUnsafeDuration()
    }
    if !flags.Changed("allow-unknown-input") {
        o.AllowUnknown = defaults.AllowUnknownInput()
    }
}
```

`Prepare` bridges from cobra:

```go
func (o *loopOptions) Prepare(cmd *cobra.Command) error {
    o.resolveConfigDefaults(cmdctx.EvaluatorFromCmd(cmd), cmd.Flags())
    o.normalize()
    return nil
}
```

The nil guard handles commands that run without a project config
(e.g. `--help`), preventing the latent nil-pointer panic on
`eval.MaxUnsafeDuration()` when `EvaluatorFromCmd` returns nil.

### 2. Fail-fast OutDir validation in Prepare

**Problem**: If `--out` points to an unwritable location, the user
doesn't find out until after the expensive "apply before" phase
completes. The fix-loop writes 4 artifacts — failing late wastes
CI minutes.

**Change**: Add a lightweight directory check in `normalize` (called
from `Prepare`). If `--out` is non-empty, verify the parent exists
or can be created.

```go
func (o *loopOptions) normalize() error {
    o.BeforeDir = fsutil.CleanUserPath(o.BeforeDir)
    o.AfterDir = fsutil.CleanUserPath(o.AfterDir)
    o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
    o.OutDir = fsutil.CleanUserPath(o.OutDir)

    if o.OutDir != "" {
        if err := fsutil.EnsureDir(o.OutDir, 0o700); err != nil {
            return fmt.Errorf("create output directory %s: %w", o.OutDir, err)
        }
    }
    return nil
}
```

`Prepare` propagates the error:

```go
func (o *loopOptions) Prepare(cmd *cobra.Command) error {
    o.resolveConfigDefaults(cmdctx.EvaluatorFromCmd(cmd), cmd.Flags())
    return o.normalize()
}
```

Note: Need to verify `fsutil.EnsureDir` or equivalent exists. If not,
use `os.MkdirAll` directly — the directory will be created by the
artifact writer anyway, so an early mkdir is safe.

## No Change Needed

### ToRequest

Already implemented with `loopResolved` return type containing
`LoopRequest` and `ports.Clock`. No further changes.

### BindFlags

Flag registration is clean and follows the standard pattern.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/fix/loop_options.go` | Add `configDefaults` interface, refactor `resolveConfigDefaults` signature, add OutDir validation in `normalize`, propagate error from `Prepare` |

## Acceptance

- `resolveConfigDefaults` accepts interface + `*pflag.FlagSet`
- Nil evaluator doesn't panic
- Non-empty `--out` directory is validated in `Prepare`
- `Prepare` returns error (was always `nil` before)
- `go vet ./cmd/enforce/fix/...` clean
- `make test` zero failures
