# Plan: Refactor cmd/apply/options.go

## Problem

`options.go` has three Go anti-patterns:

1. **Stored context in cobraState**: `cobraState.Ctx` stores
   `context.Context` in a struct. Context should flow through function
   parameters. Every downstream function (`runApply`, `runDryRun`,
   `runStandardApply`, `runner.Run`) already receives `ctx` explicitly
   via `cs.Ctx` — the field is just a pass-through vehicle.

2. **Methods on mutable options**: `Resolve`, `buildEvaluatorInput`,
   `parseDomainWith`, `ResolveStandardIO`, `ResolveDryRun`,
   `resolvePathInference`, `buildClock` are all methods on
   `*ApplyOptions`. This makes data flow opaque — readers can't tell
   which fields each method reads without tracing through the receiver.
   Go prefers functions that take what they need.

3. **Mirror struct in parseDomainWith**: Creates a throwaway
   `appeval.Options` to call `Validate()`, duplicating 5 fields from
   `ApplyOptions` just to parse them. Should call validation directly.

## Current State

```
cobraState.Ctx → passed through cs.Ctx → used in runDryRun, runner.Run, runStandardApply
ApplyOptions.Resolve(cs)       → reads o.ControlsDir, o.ObservationsDir, o.Profile, ...
ApplyOptions.buildEvaluatorInput(dirs, cfgPath) → reads o.MaxUnsafeDuration, o.NowTime, ...
ApplyOptions.parseDomainWith(obsDir)            → creates throwaway Options, validates
ApplyOptions.ResolveStandardIO(cs)              → reads o.Format, cs.FormatChanged
ApplyOptions.ResolveDryRun(cs)                  → reads o.*, cs.*
```

## Changes

### 1. Remove `Ctx` from `cobraState`

Pass `ctx` explicitly in `runApply` to functions that need it.

```go
// Before
type cobraState struct {
    Ctx    context.Context  // REMOVE
    Logger *slog.Logger
    // ...
}
func runApply(p *compose.Provider, opts *ApplyOptions, cs cobraState) error {
    return runDryRun(cs.Ctx, p, dryCfg)
}

// After
func runApply(ctx context.Context, p *compose.Provider, opts *ApplyOptions, cs cobraState) error {
    return runDryRun(ctx, p, dryCfg)
}
```

**Files:** `cmd/apply/options.go`, `cmd/apply/run.go`, `cmd/apply/cmd.go`
(the RunE that creates cobraState and calls runApply).

### 2. Convert receiver methods to functions

Convert methods that only read `ApplyOptions` fields into functions that
take the specific values they need.

**`resolvePathInference`** — reads `o.ControlsDir`, `o.ObservationsDir`,
`o.controlsSet`. Convert to function:

```go
// Before
func (o *ApplyOptions) resolvePathInference(obsChanged bool) (compose.EvalContext, error)

// After
func resolvePathInference(controlsDir, observationsDir string, controlsSet, obsChanged bool) (compose.EvalContext, error)
```

**`parseDomainWith`** — reads `o.MaxUnsafeDuration`, `o.NowTime`,
`o.IntegrityManifest`, `o.IntegrityPublicKey`. Convert to function:

```go
// Before
func (o *ApplyOptions) parseDomainWith(observationsDir string) (appeval.ParsedOptions, error)

// After
func parseDomainOptions(maxUnsafe, nowTime, obsDir, manifest, pubKey string) (appeval.ParsedOptions, error)
```

**`buildClock`** — reads `o` only for the already-parsed `now` time.
Convert to standalone function:

```go
// Before
func (o *ApplyOptions) buildClock(now time.Time) ports.Clock

// After
func buildClock(now time.Time) ports.Clock
```

**`Resolve`** — this is the main orchestrator. Keep as a method since it
coordinates multiple steps using `o.*` fields. But have it call the new
standalone functions instead of methods.

**`buildEvaluatorInput`** — reads `o.MaxUnsafeDuration`, `o.NowTime`,
etc. Keep as method since it reads 6+ fields and is called from
`runStandardApply`. Converting it would require passing too many params.

**`ResolveStandardIO`** — reads `o.Format`. Keep as method, only 1 field.

**`ResolveDryRun`** — reads many fields. Keep as method.

### 3. Simplify `parseDomainWith`

Currently creates a throwaway `appeval.Options` struct just to validate:

```go
// Before
func (o *ApplyOptions) parseDomainWith(observationsDir string) (appeval.ParsedOptions, error) {
    parsed, err := (appeval.Options{
        MaxUnsafeDuration:  o.MaxUnsafeDuration,
        NowTime:            o.NowTime,
        ObservationsSource: appeval.ObservationSource(observationsDir),
        IntegrityManifest:  o.IntegrityManifest,
        IntegrityPublicKey: o.IntegrityPublicKey,
    }).Validate()
```

Replace with a direct call to the parsing logic:

```go
// After
func parseDomainOptions(maxUnsafe, nowTime, obsDir string) (appeval.ParsedOptions, error) {
    return appeval.ParseAndValidate(maxUnsafe, nowTime, obsDir)
}
```

This requires checking if `appeval.ParseAndValidate` exists or can be
extracted from `Options.Validate()`.

### 4. Consistent error variable reuse

```go
// Before
projCfg, cfgPath, cfgErr := projconfig.FindProjectConfigWithPath("")
if cfgErr != nil { ... }

// After
projCfg, cfgPath, err := projconfig.FindProjectConfigWithPath("")
if err != nil { ... }
```

## Files Changed

| File | Change |
|------|--------|
| `cmd/apply/options.go` | Remove Ctx from cobraState, convert 3 methods to functions, simplify parseDomainWith, reuse err |
| `cmd/apply/run.go` | Pass ctx to runApply, remove cs.Ctx references |
| `cmd/apply/cmd.go` | Update RunE to pass ctx separately |
| `cmd/apply/unit_test.go` | Update test helpers if cobraState changes |

## What NOT to Change

- **Keep `Resolve` as a method**: It reads 8+ fields from `ApplyOptions`
  and is the main orchestrator. Converting it to a function would require
  a massive parameter list.
- **Keep `buildEvaluatorInput` as a method**: Reads 6+ fields, called
  from one place. Same rationale.
- **Keep `ResolveDryRun` as a method**: Reads many fields from `o` and
  `cs`.
- **No functional options**: Only 1 caller in production.

## Acceptance

- `context.Context` not stored in `cobraState`
- `resolvePathInference`, `parseDomainWith`, `buildClock` are standalone
  functions (not methods)
- `go build ./...` clean
- `go test ./...` zero failures
- `make clig-check` passes
- `make script-test` passes
