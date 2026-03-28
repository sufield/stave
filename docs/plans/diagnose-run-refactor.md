# Plan: Refactor cmd/diagnose/run.go

## Problem

`Runner` stores factory functions (`compose.ObsRepoFactory`,
`compose.CtlRepoFactory`) and calls them inside `newDiagnoseRun`.
This means repository initialization (disk I/O, YAML parsing)
happens inside the runner, making it hard to test without mocking
factories.

## Changes

### 1. Initialize repos in RunE, pass to Runner

Move `newObsRepo()` and `newCtlRepo()` calls from `newDiagnoseRun`
to the RunE block. Runner takes initialized interfaces.

```go
// Before
type Runner struct {
    NewObsRepo compose.ObsRepoFactory
    NewCtlRepo compose.CtlRepoFactory
    Clock      ports.Clock
}

// After
type Runner struct {
    ObsRepo appcontracts.ObservationRepository
    CtlRepo appcontracts.ControlRepository
    Clock   ports.Clock
}
```

### 2. Simplify newDiagnoseRun

With repos already initialized, `newDiagnoseRun` becomes a one-liner:

```go
// Before
func (r *Runner) newDiagnoseRun() (*appdiagnose.Run, error) {
    obsLoader, err := r.NewObsRepo()  // factory call
    ctlLoader, err := r.NewCtlRepo()  // factory call
    return appdiagnose.NewRun(obsLoader, ctlLoader)
}

// After
func (r *Runner) newDiagnoseRun() (*appdiagnose.Run, error) {
    return appdiagnose.NewRun(r.ObsRepo, r.CtlRepo)
}
```

### 3. Update RunE caller

```go
// Before
runner := NewRunner(newObsRepo, newCtlRepo, cfg.Clock)

// After
obsRepo, err := newObsRepo()
if err != nil { return err }
ctlRepo, err := newCtlRepo()
if err != nil { return err }
runner := NewRunner(obsRepo, ctlRepo, cfg.Clock)
```

### 4. Simplify buildAppConfig switch

The `switch` for PreviousOutput has two nearly identical branches
(stdin vs file). Unify using `os.Open` for files and keeping
`cfg.Stdin` for `-`.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/run.go` | Runner takes interfaces, simplify newDiagnoseRun |
| `cmd/diagnose/commands.go` | Init repos in RunE before constructing Runner |
| `cmd/diagnose/run_test.go` | Pass mock repos directly (no factories) |

## What NOT to Change

- **buildAppConfig switch**: The two branches have different error
  messages ("from stdin" vs "from file"). Unifying loses that context.
  Keep the switch.
- **Presenter creation**: Already clean after previous refactor.

## Acceptance

- `Runner` has no factory fields (only interfaces)
- `newDiagnoseRun` doesn't call any factory
- Repos initialized in RunE
- `go test ./...` zero failures
- `make script-test` passes
