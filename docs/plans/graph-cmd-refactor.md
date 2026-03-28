# Plan: Graph Command — Add ToConfig and Slim RunE

Add `ToConfig` to `coverageOptions` to move format parsing and config
assembly out of `RunE`, matching the pattern used across gate, diff,
fix, and generate.

## Changes

### 1. Add ToConfig to coverageOptions

**Problem**: `RunE` inlines format parsing, global flag extraction,
and config struct assembly. This couples flag resolution with
execution and prevents testing config resolution independently.

**Change**: Add `ToConfig(cmd)` to `coverageOptions` in `options.go`.
Merge path normalization from `Prepare` into `ToConfig` so the
`PreRunE` hook can be removed.

```go
func (o *coverageOptions) ToConfig(cmd *cobra.Command) (config, error) {
    format, err := ParseFormat(o.FormatRaw)
    if err != nil {
        return config{}, fmt.Errorf("invalid format: %w", err)
    }
    gf := cliflags.GetGlobalFlags(cmd)
    return config{
        ControlsDir:     fsutil.CleanUserPath(o.ControlsDir),
        ObservationsDir: fsutil.CleanUserPath(o.ObsDir),
        Format:          format,
        AllowUnknown:    o.AllowUnknown,
        Sanitizer:       gf.GetSanitizer(),
        Stdout:          cmd.OutOrStdout(),
    }, nil
}
```

### 2. Remove PreRunE and Prepare

Path normalization moves into `ToConfig`. `Prepare` and the
`PreRunE` hook become unnecessary.

### 3. Move completion registration into BindFlags

Currently `cmd.RegisterFlagCompletionFunc("format", ...)` is called
after `opts.BindFlags(cmd)` in `newCoverageCmd`. Move it into
`BindFlags` for encapsulation, matching the generate pattern.

### 4. Slim RunE

```go
RunE: func(cmd *cobra.Command, _ []string) error {
    cfg, err := opts.ToConfig(cmd)
    if err != nil {
        return err
    }
    runner := newRunner(
        func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
            return compose.LoadControlsFrom(ctx, newCtlRepo, dir)
        },
        loadSnapshots,
    )
    return runner.Run(cmd.Context(), cfg)
},
```

## No Change Needed

### run.go

Runner, config, Run, and all helpers are already well-structured.

### NewCmd (parent)

Already a clean group command with `AddCommand`. No change.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/graph/options.go` | Add `ToConfig`, remove `Prepare`, move completion into `BindFlags` |
| `cmd/enforce/graph/cmd.go` | Remove `PreRunE`, slim `RunE` to use `opts.ToConfig` |

## Acceptance

- `ToConfig` handles format parsing, path cleaning, and config assembly
- No `PreRunE` hook
- `RunE` is: resolve config → create runner → execute
- `go vet ./cmd/enforce/graph/...` clean
- `make test` zero failures
