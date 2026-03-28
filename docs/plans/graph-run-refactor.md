# Plan: Graph Runner — Export Types, Pre-allocate, Wrap Errors

Export core types for test/library use, add capacity hints to hot-path
allocations, and wrap bare errors with stage context.

## Changes

### 1. Export core types

| Before | After |
|--------|-------|
| `coverageEdge` | `CoverageEdge` |
| `coverageResult` | `CoverageResult` |
| `runner` | `Runner` |
| `newRunner` | `NewRunner` |

All internal references and `cmd.go` call site updated.

### 2. Pre-allocate edges slice in coverageEdges

**Problem**: `edges := make([]CoverageEdge, 0)` has zero capacity.
In the nested loop (controls × assets), every `append` may trigger
a reallocation.

**Change**: Hint capacity based on asset count — a reasonable upper
bound since each asset can be covered by at most one edge per
control.

```go
// Before
edges := make([]coverageEdge, 0)

// After
edges := make([]CoverageEdge, 0, len(assetIDs))
```

### 3. Wrap bare errors in Run and loadArtifacts

Five bare error returns lack stage context:

| Location | Wrapped |
|----------|---------|
| `Run` dircheck controls | `"invalid controls directory: %w"` |
| `Run` dircheck observations | `"invalid observations directory: %w"` |
| `Run` loadArtifacts | `"loading artifacts: %w"` |
| `loadArtifacts` LoadControls | `"load controls: %w"` |
| `loadArtifacts` LoadSnapshots | `"load snapshots: %w"` |

### 4. Initialize nil slices in uncoveredAssets

**Problem**: `uncoveredAssets` uses `var out []string` which stays
nil when all assets are covered, producing `"uncovered_assets": null`
in JSON output.

**Change**: Initialize with `make([]string, 0)` matching the
`CompareBaseline` pattern. Remove the nil guards in `writeJSON`.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/graph/run.go` | Export types, pre-allocate edges, wrap errors, init nil slices |
| `cmd/enforce/graph/cmd.go` | Update `newRunner` → `NewRunner` call |

## Acceptance

- `CoverageResult` and `CoverageEdge` are exported
- `NewRunner` constructor exported and used in `cmd.go`
- Edges slice pre-allocated with capacity hint
- All error returns wrapped with `%w`
- No nil slices in JSON output
- `go vet ./cmd/enforce/graph/...` clean
- `make test` zero failures
