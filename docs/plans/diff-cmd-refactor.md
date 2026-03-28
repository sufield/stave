# Plan: Snapshot Diff Command — Constant Alignment

Final cleanup for `cmd/enforce/diff/`: align CLI string literals with
domain constants so the command and domain layer never get out of sync.

## Remaining Changes

### 1. Use domain constants in parseChangeTypes

**Problem**: `parseChangeTypes` in `options.go` uses string literals
`"added"`, `"removed"`, `"modified"` in the switch statement. The
domain already defines `asset.ChangeAdded`, `asset.ChangeRemoved`,
`asset.ChangeModified` as typed constants. If a constant value changes,
the CLI validation silently drifts.

```go
// Before (options.go:98-100)
switch val {
case "added", "removed", "modified":
    out = append(out, asset.ChangeType(val))

// After
ct := asset.ChangeType(val)
switch ct {
case asset.ChangeAdded, asset.ChangeRemoved, asset.ChangeModified:
    out = append(out, ct)
```

### 2. Use domain constants in flag completion

**Problem**: `cmd.go` registers completion values as string literals.
Same drift risk.

```go
// Before (cmd.go:64)
_ = cmd.RegisterFlagCompletionFunc("change-type",
    cliflags.CompleteFixed("added", "removed", "modified"))

// After
_ = cmd.RegisterFlagCompletionFunc("change-type",
    cliflags.CompleteFixed(
        string(asset.ChangeAdded),
        string(asset.ChangeRemoved),
        string(asset.ChangeModified),
    ))
```

Imports added to `cmd.go`: `github.com/sufield/stave/pkg/alpha/domain/asset`.

## No Change Needed

### Runner factory pattern

The diff package uses an Options-to-Config pattern: global flags
(`--quiet`, `--sanitize`, stdout/stderr) are extracted in
`opts.ToConfig(cmd)` and passed to `runner.Run` via the `config`
struct. The runner itself only holds the injected `SnapshotLoader`.
This is a cleaner separation than embedding I/O concerns in the
runner constructor — the runner is testable with just a mock loader
and a config value. No change to `newRunner`.

### Context propagation

`runner.Run` accepts `ctx` and passes it to `r.LoadSnapshots(ctx, dir)`.
Already correct.

### Error wrapping

All errors in `computeDelta` are wrapped with `%w` and descriptive
context. `Run` returns them directly (no double-wrapping needed since
`computeDelta` provides sufficient context).

### Streaming JSON decoder

The snapshot loader uses `json.Unmarshal` on full file contents in
`internal/adapters/observations/loader_core.go`. Switching to a
streaming `json.Decoder` would reduce memory pressure for large
snapshots. This is an adapter-layer concern that affects all snapshot
consumers — out of scope for this command-level plan.

### Command structure

`RunE` already follows the idiomatic pattern:
`opts.ToConfig(cmd)` → `newRunner(loadSnapshots)` → `runner.Run(cmd.Context(), cfg)`.
`PreRunE` handles path normalization via `opts.Prepare`. No change.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/diff/options.go` | Use `asset.ChangeAdded` etc. in switch |
| `cmd/enforce/diff/cmd.go` | Use `asset.Change*` constants in completion, add `asset` import |

## Acceptance

- `parseChangeTypes` switch uses domain constants, not string literals
- Flag completion values derived from domain constants
- `go vet ./cmd/enforce/diff/...` clean
- `make test` zero failures
