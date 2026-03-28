# Plan: Status Command — Add ToConfig and Remove PreRunE

Move format resolution and path cleaning into `options.ToConfig`,
remove `PreRunE`/`Prepare`/`resolveFormat`, and slim `RunE` to
match the established pattern.

## Changes

### 1. Add ToConfig to options

**Problem**: `RunE` manually calls `opts.resolveFormat(cmd)` and
assembles the config inline. `Prepare` only cleans one path.
Format resolution is a separate method. This splits config assembly
across three locations.

**Change**: Merge `Prepare`, `resolveFormat`, and config assembly
into a single `ToConfig(cmd)` method.

```go
func (o *options) ToConfig(cmd *cobra.Command) (config, error) {
    format, err := compose.ResolveFormatValue(cmd, o.Format)
    if err != nil {
        return config{}, err
    }
    return config{
        Dir:    fsutil.CleanUserPath(o.Dir),
        Format: format,
        Stdout: cmd.OutOrStdout(),
        Stderr: cmd.ErrOrStderr(),
    }, nil
}
```

Remove `Prepare` and `resolveFormat` — both absorbed into `ToConfig`.

### 2. Remove PreRunE and slim RunE

```go
// Before
PreRunE: func(cmd *cobra.Command, _ []string) error {
    return opts.Prepare(cmd)
},
RunE: func(cmd *cobra.Command, _ []string) error {
    format, err := opts.resolveFormat(cmd)
    if err != nil {
        return err
    }
    resolver, err := projctx.NewResolver()
    ...
    return runner.Run(config{
        Dir: opts.Dir, Format: format, ...
    })
},

// After
RunE: func(cmd *cobra.Command, _ []string) error {
    cfg, err := opts.ToConfig(cmd)
    if err != nil {
        return err
    }
    resolver, err := projctx.NewResolver()
    if err != nil {
        return err
    }
    return NewRunner(resolver).Run(cfg)
},
```

### 3. Remove redundant CleanUserPath in Run

`run.go:35` calls `fsutil.CleanUserPath(cfg.Dir)` but `ToConfig`
already cleans the path. Remove the duplicate.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/status/options.go` | Add `ToConfig`, remove `Prepare`/`resolveFormat` |
| `cmd/enforce/status/cmd.go` | Remove `PreRunE`, slim `RunE` |
| `cmd/enforce/status/run.go` | Remove redundant `CleanUserPath` |

## Acceptance

- `ToConfig` handles format resolution and path cleaning
- No `PreRunE` hook
- `RunE` is: resolve config → create resolver → run
- No duplicate path cleaning in `Run`
- `go vet ./cmd/enforce/status/...` clean
- `make test` zero failures
