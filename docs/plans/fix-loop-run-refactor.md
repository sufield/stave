# Plan: Fix Loop Runner — Dependency Assembly and Error Context

Extract dependency setup from `Loop` into a helper and wrap bare
errors with stage context for CI log readability.

## Changes

### 1. Extract buildLoopInfra helper

**Problem**: `Loop` mixes dependency setup (control repo, obs repo
factory, artifact writer, envelope builder) with execution logic.
At 50 lines, it's hard to see the orchestration flow.

**Change**: Extract a `buildLoopInfra` method that returns all
four dependencies, wrapping initialization errors with context.

```go
type loopInfra struct {
    deps   appfix.LoopDeps
    writer *appfix.ArtifactWriter
    eb     *appfix.EnvelopeBuilder
}

func (r *Runner) buildLoopInfra(req LoopRequest) (loopInfra, error) {
    controlRepo, err := r.NewCtlRepo()
    if err != nil {
        return loopInfra{}, fmt.Errorf("init control repo: %w", err)
    }

    writer, err := appfix.NewArtifactWriter(
        req.OutDir,
        appfix.WriteOptions{
            Overwrite:     r.FileOptions.Overwrite,
            AllowSymlinks: r.FileOptions.AllowSymlinks,
            DirPerms:      r.FileOptions.DirPerms,
        },
        req.Stdout,
        fsutil.SafeFileSystem{
            Overwrite:    r.FileOptions.Overwrite,
            AllowSymlink: r.FileOptions.AllowSymlinks,
        },
    )
    if err != nil {
        return loopInfra{}, fmt.Errorf("init artifact writer: %w", err)
    }

    return loopInfra{
        deps: appfix.LoopDeps{
            ObservationRepoFactory: func() (contracts.ObservationRepository, error) {
                return r.NewObsRepo()
            },
            ControlRepo: controlRepo,
        },
        writer: writer,
        eb:     r.newEnvelopeBuilder(),
    }, nil
}
```

### 2. Slim Loop to orchestration only

After extraction, `Loop` becomes:

```go
func (r *Runner) Loop(ctx context.Context, req LoopRequest) error {
    r.service.Sanitizer = r.Sanitizer

    infra, err := r.buildLoopInfra(req)
    if err != nil {
        return err
    }

    err = r.service.Loop(ctx, appfix.LoopRequest{
        BeforeDir:         req.BeforeDir,
        AfterDir:          req.AfterDir,
        ControlsDir:       req.ControlsDir,
        OutDir:            req.OutDir,
        MaxUnsafeDuration: req.MaxUnsafeDuration,
        AllowUnknown:      req.AllowUnknown,
        Stdout:            req.Stdout,
        Stderr:            req.Stderr,
    }, infra.deps, infra.writer, infra.eb)

    if errors.Is(err, appfix.ErrViolationsRemaining) {
        return ui.ErrViolationsFound
    }
    return err
}
```

### 3. Wrap initialization errors

The two bare `return err` calls in the current code get wrapped
with `fmt.Errorf` inside `buildLoopInfra`:

| Current | Wrapped |
|---------|---------|
| `return err` (NewCtlRepo) | `"init control repo: %w"` |
| `return amErr` (NewArtifactWriter) | `"init artifact writer: %w"` |

## No Change Needed

### Context propagation to NewCtlRepo

`NewCtlRepo` is typed as `func() (ControlRepository, error)` —
it doesn't accept `context.Context`. Changing the factory type
would be a cross-cutting change affecting `compose.CtlRepoFactory`
and all call sites. Out of scope for this file.

### LoopRequest mapping

The 1:1 field copy from `LoopRequest` to `appfix.LoopRequest` is
explicit and grep-friendly. Extracting a `mapToAppRequest` helper
would just move the same code without improving readability.

### ArtifactWriter stdout-only mode

The writer already handles empty `OutDir` by writing only to stdout.
No change needed.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/fix/loop_run.go` | Extract `loopInfra` + `buildLoopInfra`, slim `Loop`, wrap errors |

## Acceptance

- `Loop` is ~15 lines of orchestration
- `buildLoopInfra` owns all dependency setup with wrapped errors
- `go vet ./cmd/enforce/fix/...` clean
- `make test` zero failures
