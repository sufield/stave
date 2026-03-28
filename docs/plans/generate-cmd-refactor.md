# Plan: Generate Command — Extract Options Struct

Move flag variables from `NewCmd` local scope into an `options`
struct with `BindFlags` and `ToConfig` methods, matching the pattern
used in gate, diff, and fix.

## Changes

### 1. Extract options struct with BindFlags and ToConfig

**Problem**: `NewCmd` declares flags as local variables and performs
mode parsing + path cleaning inline in `RunE`. This couples flag
definition with execution logic and prevents testing config
resolution without a full Cobra command.

**Change**: Create an `options` struct in `cmd.go` with three methods:

```go
type options struct {
    InPath  string
    OutDir  string
    ModeRaw string
    DryRun  bool
}

func defaultOptions() options {
    return options{
        OutDir:  "output",
        ModeRaw: string(ModePAB),
    }
}

func (o *options) BindFlags(cmd *cobra.Command) {
    f := cmd.Flags()
    f.StringVarP(&o.InPath, "in", "i", "", "Path to evaluation JSON input (required)")
    f.StringVar(&o.OutDir, "out", o.OutDir, "Output directory for generated templates")
    f.StringVar(&o.ModeRaw, "mode", o.ModeRaw, "Enforcement mode: pab|scp")
    f.BoolVar(&o.DryRun, "dry-run", o.DryRun, "Preview planned paths without writing files")
    _ = cmd.MarkFlagRequired("in")
    _ = cmd.RegisterFlagCompletionFunc("mode",
        cliflags.CompleteFixed(string(ModePAB), string(ModeSCP)))
}

func (o *options) ToConfig(cmd *cobra.Command) (Config, error) {
    mode, err := ParseMode(o.ModeRaw)
    if err != nil {
        return Config{}, fmt.Errorf("invalid mode: %w", err)
    }
    return Config{
        InputPath: fsutil.CleanUserPath(o.InPath),
        OutDir:    fsutil.CleanUserPath(o.OutDir),
        Mode:      mode,
        DryRun:    o.DryRun,
        Stdout:    cmd.OutOrStdout(),
    }, nil
}
```

### 2. Slim NewCmd RunE

`RunE` becomes three steps matching the established pattern:

```go
RunE: func(cmd *cobra.Command, _ []string) error {
    cfg, err := opts.ToConfig(cmd)
    if err != nil {
        return err
    }
    gf := cliflags.GetGlobalFlags(cmd)
    runner := &Runner{
        FileOptions: fileout.FileOptions{
            Overwrite:     gf.Force,
            AllowSymlinks: gf.AllowSymlinkOut,
            DirPerms:      0o700,
        },
    }
    return runner.Run(cmd.Context(), cfg)
},
```

Flag registration and completion move to `opts.BindFlags(cmd)` after
the command construction.

## No Change Needed

### run.go

`Runner`, `Config`, `Run`, `buildPlan`, and all helpers are already
well-structured. No changes needed.

### Input validation

`validateInputPath` in `run.go` already checks file existence via
`os.Stat`. No duplicate check needed in options.

### Error wrapping in ParseMode

`ParseMode` already returns a `ui.EnumError` with clear messaging.
`ToConfig` wraps it with `"invalid mode: %w"` for additional context.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/generate/cmd.go` | Extract `options` struct, `BindFlags`, `ToConfig`; slim `NewCmd` |

## Acceptance

- Flag variables no longer declared as local vars in `NewCmd`
- `ToConfig` handles mode parsing and path cleaning
- `RunE` is three steps: resolve config, create runner, execute
- `go vet ./cmd/enforce/generate/...` clean
- `make test` zero failures
