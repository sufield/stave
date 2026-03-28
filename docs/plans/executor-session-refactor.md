# Plan: Executor Session — Inject Resolver and Consolidate Finalize

Accept the resolver as a parameter in `persistSessionStateIfApplicable`
instead of creating it internally. Create the resolver once in
`finalizeExecute` and pass it through.

## Changes

### 1. Accept resolver in persistSessionStateIfApplicable

**Problem**: `persistSessionStateIfApplicable` calls
`projctx.NewResolver()` internally, making it impossible to test
without filesystem access.

**Change**: Accept `*projctx.Resolver` as parameter with nil guard.

```go
// Before
func persistSessionStateIfApplicable(args []string) string {
    resolver, err := projctx.NewResolver()
    if err != nil {
        return ""
    }
    ...
}

// After
func persistSessionStateIfApplicable(resolver *projctx.Resolver, args []string) string {
    if resolver == nil {
        return ""
    }
    projectRoot, err := resolver.DetectProjectRoot(resolver.WorkingDir)
    if err != nil {
        return ""
    }
    _ = projctx.SaveSession(projectRoot, args)
    return projectRoot
}
```

### 2. Create resolver once in finalizeExecute

**Problem**: The resolver is only used by
`persistSessionStateIfApplicable`, but creating it at the
`finalizeExecute` level makes it available for future cleanup
tasks without redundant construction.

**Change**: Update `finalizeExecute` in `executor.go` to create
the resolver and pass it.

```go
func (a *App) finalizeExecute(args []string, showFirstRunHint bool, firstRunMarkerPath string) {
    markFirstRunHintSeenIfNeeded(showFirstRunHint, firstRunMarkerPath)
    a.printNoProjectHintIfNeeded(args)

    resolver, _ := projctx.NewResolver()
    projectRoot := persistSessionStateIfApplicable(resolver, args)
    a.printWorkflowHandoff(args, projectRoot)
}
```

The `_` on `NewResolver` error is intentional —
`persistSessionStateIfApplicable` already guards against nil.

## No Change Needed

### printWorkflowHandoff

Already takes `projectRoot` as parameter. Clean leaf function.

### HintService / PostExec / context timeouts

These are larger architectural changes that require modifying
the `App` struct and `main.go`. Session persistence is local
file I/O that completes in microseconds — a 250ms timeout adds
complexity without solving a real performance problem.

## Files Changed

| File | Change |
|------|--------|
| `cmd/executor_session.go` | Accept `*projctx.Resolver` param, add nil guard |
| `cmd/executor.go` | Create resolver in `finalizeExecute`, pass to session func |

## Acceptance

- `persistSessionStateIfApplicable` accepts resolver, doesn't create its own
- Nil resolver returns "" without panic
- Resolver created once in `finalizeExecute`
- `go vet ./cmd/...` clean
- `make test` zero failures
