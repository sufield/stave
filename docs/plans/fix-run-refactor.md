# Plan: Fix Runner — Guard Loop Prerequisites

Add nil guards for Loop-only dependencies that are set after
construction, preventing nil-pointer panics if a caller forgets
to wire them.

## Changes

### 1. Validate NewCtlRepo and NewObsRepo in buildLoopInfra

**Problem**: `NewCtlRepo` and `NewObsRepo` are public fields set
by the caller after `NewRunner()` returns. If `Loop()` is called
without setting them, `r.NewCtlRepo()` panics with a nil function
call. This is a latent bug — currently prevented only by the
`newLoopRunner` factory in `cmd.go`, but `Runner` is exported and
`NewRunner` doesn't require them.

**Change**: Add nil guards at the top of `buildLoopInfra` in
`loop_run.go`:

```go
func (r *Runner) buildLoopInfra(req LoopRequest) (loopInfra, error) {
    if r.NewCtlRepo == nil {
        return loopInfra{}, fmt.Errorf("fix-loop requires a control repository factory")
    }
    if r.NewObsRepo == nil {
        return loopInfra{}, fmt.Errorf("fix-loop requires an observation repository factory")
    }
    // ... existing code
}
```

This turns a nil-pointer panic into a clear error message.

## No Change Needed

### NewRunner construction

`crypto.NewHasher()` and `remediation.NewPlanner` are lightweight
(sha256 wrapper, no state). Injecting them adds indirection without
benefit — tests already construct the real planner via
`newTestRunner`. No change.

### newEnvelopeBuilder

Returns a plain struct with no I/O. No context needed.

### Functional options / InitLoop

A nil guard is simpler and doesn't change the public API. The
`newLoopRunner` factory in `cmd.go` already ensures correct wiring
for production use. The nil guard catches misuse in tests or
future callers.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/fix/loop_run.go` | Add nil guards for `NewCtlRepo`/`NewObsRepo` in `buildLoopInfra` |

## Acceptance

- Calling `Loop()` without setting `NewCtlRepo` returns a clear error
- Calling `Loop()` without setting `NewObsRepo` returns a clear error
- No nil-pointer panics from unset factories
- `go vet ./cmd/enforce/fix/...` clean
- `make test` zero failures
