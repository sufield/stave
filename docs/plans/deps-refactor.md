# Plan: Refactor cmd/apply/deps.go

## Problem

`deps.go` has three Go anti-patterns:

1. **Stored context**: `Builder.Ctx` stores `context.Context` in a struct.
   Go convention: context flows through function parameters, not struct
   fields. Storing it risks stale contexts and obscures cancellation flow.

2. **God object parameter**: `NewBuilder` takes `*compose.Provider` and
   extracts three factories. The caller doesn't know which parts of
   Provider are actually used.

3. **Mirror struct**: `ApplyBuilderInput` (22 fields) mirrors
   `BuildDependenciesInput` (already in `build.go`). The Builder should
   construct `BuildDependenciesInput` directly, eliminating the
   intermediate struct.

## Current Flow

```
run.go:executeEvaluation(ctx)
  -> NewBuilder(ctx, logger, provider, opts, params, sio)  // stores ctx
  -> builder.Build(plan)                                    // reads b.Ctx
    -> buildAdapters()
    -> loadExemptionConfig()
    -> buildProjectConfigFromLoaded()
    -> NewPredicateEval()
    -> BuildApplyDeps(ApplyBuilderInput{Ctx: b.Ctx, ...})  // mirror struct
      -> BuildDependencies(BuildDependenciesInput{...})     // real work
```

## Target Flow

```
run.go:executeEvaluation(ctx)
  -> NewBuilder(opts, params, sio)               // no ctx, no provider
  -> builder.Build(ctx, plan)                     // ctx as first param
    -> buildAdapters()
    -> loadExemptionConfig()
    -> buildProjectConfigFromLoaded()
    -> NewPredicateEval()
    -> BuildDependencies(BuildDependenciesInput{  // direct, no mirror
         Context: ctx,
         ...
       })
```

## Changes

### 1. Remove `Ctx` from Builder, pass to `Build`

**File: `cmd/apply/deps.go`**

```go
// Before
type Builder struct {
    Ctx    context.Context  // REMOVE
    // ...
}
func (b *Builder) Build(plan *appeval.EvaluationPlan) (*appeval.ApplyDeps, error)

// After
type Builder struct {
    // ... (no Ctx)
}
func (b *Builder) Build(ctx context.Context, plan *appeval.EvaluationPlan) (*appeval.ApplyDeps, error)
```

**File: `cmd/apply/run.go`** — Update call site:
```go
// Before
builder := NewBuilder(ctx, logger, p, opts, params, sio)
deps, err := builder.Build(ec.Plan)

// After
builder := NewBuilder(logger, p, opts, params, sio)
deps, err := builder.Build(ctx, ec.Plan)
```

### 2. Remove `compose.Provider` from `NewBuilder`

Take the three specific factories instead of the god object.

```go
// Before
func NewBuilder(ctx context.Context, logger *slog.Logger, p *compose.Provider,
    opts *ApplyOptions, params applyParams, sio standardIO) *Builder

// After
func NewBuilder(logger *slog.Logger, opts *ApplyOptions, params applyParams, sio standardIO) *Builder
```

The factories (`NewFindingWriter`, `NewCtlRepo`, `NewStdinObsRepo`) are
already stored as individual fields on the Builder. Set them from the
caller in `run.go` using the Provider:

```go
builder := NewBuilder(ec.Logger, ec.Opts, ec.Params, ec.IO)
builder.NewFindingWriter = p.NewFindingWriter
builder.NewCtlRepo = p.NewControlRepo
builder.NewStdinObsRepo = p.NewStdinObsRepo
```

This is one extra line but makes the dependency surface explicit.

### 3. Eliminate `ApplyBuilderInput` mirror struct

`Build()` should construct `BuildDependenciesInput` directly instead of
going through `ApplyBuilderInput` -> `BuildApplyDeps` ->
`BuildDependenciesInput`.

```go
// Before
deps, err := appeval.BuildApplyDeps(appeval.ApplyBuilderInput{
    Ctx: b.Ctx, ...22 fields...
})

// After
built, err := appeval.BuildDependencies(appeval.BuildDependenciesInput{
    Context: ctx,
    Logger:  b.Logger,
    Plan:    *plan,
    Adapters: appeval.Adapters{...},
    Runtime:  appeval.RuntimeConfig{...},
    Writers:  appeval.OutputWriters{...},
    Project:  appeval.ProjectScope{...},
})
```

Then delete `ApplyBuilderInput` and `BuildApplyDeps` from `build.go`.

### 4. Reuse `err` variable (minor cleanup)

```go
// Before
projCfgInput, projCfgErr := b.buildProjectConfigFromLoaded(...)
celEval, celErr := stavecel.NewPredicateEval()

// After
projCfgInput, err := b.buildProjectConfigFromLoaded(...)
celEval, err := stavecel.NewPredicateEval()
```

## Files Changed

| File | Change |
|------|--------|
| `cmd/apply/deps.go` | Remove Ctx, remove Provider param, build directly, reuse err |
| `cmd/apply/run.go` | Pass ctx to Build(), set factories explicitly |
| `cmd/apply/unit_test.go` | Update test call sites |
| `internal/app/eval/build.go` | Delete ApplyBuilderInput + BuildApplyDeps |

## What NOT to Change

- **No functional options**: `NewBuilder` has exactly 1 caller in
  production. Functional options add API surface for no benefit.
- **No changes to `build.go` structure**: `BuildDependenciesInput` with
  its sub-structs (`Adapters`, `RuntimeConfig`, `OutputWriters`,
  `ProjectScope`) is already well-organized.
- **No changes to downstream evaluation**: The refactor stops at the
  `BuildDependencies` boundary.

## Acceptance

- `context.Context` not stored in any struct field
- `compose.Provider` not passed to `NewBuilder`
- `ApplyBuilderInput` deleted (zero references)
- `BuildApplyDeps` deleted (zero references)
- `go build ./...` clean
- `go test ./...` zero failures
- `make clig-check` passes
- `make script-test` passes
