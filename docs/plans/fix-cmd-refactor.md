# Plan: Fix Command — Factory Grouping and Config Resolution

Reduce parameter noise in `NewFixLoopCmd` and slim its `RunE` by
grouping factory dependencies and moving flag resolution into the
options layer.

## Changes

### 1. Group fix-loop factories into FixLoopDeps

**Problem**: `NewFixLoopCmd` takes three positional factory functions:

```go
func NewFixLoopCmd(
    newCELEvaluator compose.CELEvaluatorFactory,
    newCtlRepo compose.CtlRepoFactory,
    newObsRepo compose.ObsRepoFactory,
) *cobra.Command
```

Adding a fourth dependency means changing the signature and all call
sites. This applies equally to the wrapper in `enforce/commands.go`
and the wiring in `cmd/commands.go`.

**Change**: Introduce a `FixLoopDeps` struct in `cmd.go`:

```go
// FixLoopDeps groups the factory functions required by the fix-loop command.
type FixLoopDeps struct {
    NewCELEvaluator compose.CELEvaluatorFactory
    NewCtlRepo      compose.CtlRepoFactory
    NewObsRepo      compose.ObsRepoFactory
}

func NewFixLoopCmd(deps FixLoopDeps) *cobra.Command {
```

Call sites updated:

```go
// cmd/enforce/commands.go
func NewFixLoopCmd(deps fix.FixLoopDeps) *cobra.Command {
    return fix.NewFixLoopCmd(deps)
}

// cmd/commands.go — wireCISubtree
ciCmd.AddCommand(enforce.NewFixLoopCmd(fix.FixLoopDeps{
    NewCELEvaluator: p.NewCELEvaluator,
    NewCtlRepo:      p.NewControlRepo,
    NewObsRepo:      p.NewObservationRepo,
}))
```

### 2. Move duration/clock resolution to loopOptions.ToRequest

**Problem**: `RunE` manually parses `--max-unsafe` and `--now`,
extracts global flags, constructs `FileOptions`, and assembles the
`LoopRequest`. This is 20 lines of config resolution mixed with
runner construction.

**Change**: Add `ToRequest(cmd)` to `loopOptions` that returns a
resolved `LoopRequest` plus a `ports.Clock` (needed by `NewRunner`).

```go
// loop_options.go
type loopResolved struct {
    Request LoopRequest
    Clock   ports.Clock
}

func (o *loopOptions) ToRequest(cmd *cobra.Command) (loopResolved, error) {
    maxUnsafe, err := cliflags.ParseDurationFlag(o.MaxUnsafeRaw, "--max-unsafe")
    if err != nil {
        return loopResolved{}, err
    }
    clock, err := compose.ResolveClock(o.NowRaw)
    if err != nil {
        return loopResolved{}, err
    }
    return loopResolved{
        Request: LoopRequest{
            BeforeDir:         o.BeforeDir,
            AfterDir:          o.AfterDir,
            ControlsDir:       o.ControlsDir,
            OutDir:            o.OutDir,
            MaxUnsafeDuration: maxUnsafe,
            AllowUnknown:      o.AllowUnknown,
            Stdout:            cmd.OutOrStdout(),
            Stderr:            cmd.ErrOrStderr(),
        },
        Clock: clock,
    }, nil
}
```

### 3. Slim RunE with newLoopRunner factory

**Problem**: RunE manually sets `runner.NewCtlRepo`, `NewObsRepo`,
`Sanitizer`, and `FileOptions` after construction.

**Change**: Add `newLoopRunner(cmd, deps, clock)` that wires
everything including global flags.

```go
func newLoopRunner(cmd *cobra.Command, deps FixLoopDeps, clock ports.Clock) (*Runner, error) {
    gf := cliflags.GetGlobalFlags(cmd)
    celEval, err := deps.NewCELEvaluator()
    if err != nil {
        return nil, err
    }
    runner := NewRunner(celEval, clock)
    runner.NewCtlRepo = deps.NewCtlRepo
    runner.NewObsRepo = deps.NewObsRepo
    runner.Sanitizer = gf.GetSanitizer()
    runner.FileOptions = fileout.FileOptions{
        Overwrite:     gf.Force,
        AllowSymlinks: gf.AllowSymlinkOut,
        DirPerms:      0o700,
    }
    return runner, nil
}
```

The resulting `RunE` becomes:

```go
RunE: func(cmd *cobra.Command, _ []string) error {
    resolved, err := opts.ToRequest(cmd)
    if err != nil {
        return err
    }
    runner, err := newLoopRunner(cmd, deps, resolved.Clock)
    if err != nil {
        return err
    }
    return runner.Loop(cmd.Context(), resolved.Request)
},
```

## No Change Needed

### NewFixCmd

`NewFixCmd` takes a single factory (`CELEvaluatorFactory`) — no
grouping needed. Its `RunE` is already thin (5 lines).

### Context cancellation in Loop

`Loop` delegates to `r.service.Loop(ctx, ...)` which is the app
layer. Context propagation is already wired; checking `ctx.Err()`
between steps is an app-layer concern, not a command-layer one.

### Atomic report generation

The fix-loop writes 4 artifacts via `appfix.ArtifactWriter`. Making
this atomic (temp dir + rename) is an app-layer change in
`internal/app/fix/`, not in `cmd/enforce/fix/cmd.go`.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/fix/cmd.go` | Add `FixLoopDeps`, use in `NewFixLoopCmd`, add `newLoopRunner` |
| `cmd/enforce/fix/loop_options.go` | Add `loopResolved` and `ToRequest(cmd)` |
| `cmd/enforce/commands.go` | Update `NewFixLoopCmd` wrapper signature |
| `cmd/commands.go` | Update `wireCISubtree` call site |

## Acceptance

- `NewFixLoopCmd` takes `FixLoopDeps` struct instead of 3 positional args
- `loopOptions.ToRequest(cmd)` resolves duration, clock, and builds request
- `RunE` is three steps: resolve request, create runner, execute
- `NewFixCmd` unchanged
- `go vet ./...` clean
- `make test` zero failures
