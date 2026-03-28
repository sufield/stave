# Plan: Snapshot Diff Command — Unified Factory Pattern

Move global flags and I/O concerns from `config` into the `runner`
via a `newRunner(cmd, loader)` factory, matching the pattern
established in baseline and cidiff.

## Rationale

Currently `opts.ToConfig(cmd)` extracts both domain parameters
(observations dir, format, filter) and CLI concerns (quiet, sanitizer,
stdout, stderr) into a flat `config` struct. The baseline and cidiff
packages separate these: the factory wires CLI concerns into the
runner, and config carries only domain parameters. Aligning diff with
this pattern ensures global flags like `--quiet` are handled
consistently across all CI commands.

## Changes

### 1. Move CLI concerns from config to runner

```go
// Before (run.go)
type config struct {
    ObservationsDir string
    Format          ui.OutputFormat
    Filter          asset.FilterOptions
    Quiet           bool              // CLI concern
    Sanitizer       kernel.Sanitizer  // CLI concern
    Stdout          io.Writer         // CLI concern
    Stderr          io.Writer         // CLI concern
}

type runner struct {
    LoadSnapshots compose.SnapshotLoader
}

// After
type config struct {
    ObservationsDir string
    Format          ui.OutputFormat
    Filter          asset.FilterOptions
}

type runner struct {
    LoadSnapshots compose.SnapshotLoader
    Quiet         bool
    Sanitizer     kernel.Sanitizer
    Stdout        io.Writer
    Stderr        io.Writer
}
```

### 2. Extract newRunner(cmd, loader) factory

```go
// Before (run.go:33-35)
func newRunner(load compose.SnapshotLoader) *runner {
    return &runner{LoadSnapshots: load}
}

// After
func newRunner(cmd *cobra.Command, load compose.SnapshotLoader) *runner {
    gf := cliflags.GetGlobalFlags(cmd)
    stdout := cmd.OutOrStdout()
    if !gf.TextOutputEnabled() {
        stdout = io.Discard
    }
    return &runner{
        LoadSnapshots: load,
        Quiet:         gf.Quiet,
        Sanitizer:     gf.GetSanitizer(),
        Stdout:        stdout,
        Stderr:        cmd.ErrOrStderr(),
    }
}
```

### 3. Update opts.ToConfig — remove CLI concerns

`ToConfig` drops the `cmd` parameter entirely since it no longer
needs global flags or I/O. It becomes a pure options-to-config
validator.

```go
// Before (options.go:51)
func (o *Options) ToConfig(cmd *cobra.Command) (config, error) {

// After
func (o *Options) ToConfig(cmd *cobra.Command) (config, error) {
    format, err := compose.ResolveFormatValue(cmd, o.Format)
    if err != nil {
        return config{}, err
    }
    filter, err := o.buildFilter()
    if err != nil {
        return config{}, err
    }
    return config{
        ObservationsDir: o.ObservationsDir,
        Format:          format,
        Filter:          filter,
    }, nil
}
```

Note: `ToConfig` still needs `cmd` for `compose.ResolveFormatValue`
which reads the `--format` flag binding.

### 4. Update Run to use runner fields

```go
// Before
func (r *runner) Run(ctx context.Context, cfg config) error {
    progress := ui.NewRuntime(cfg.Stdout, cfg.Stderr)
    progress.Quiet = cfg.Quiet
    ...
    delta = output.SanitizeObservationDelta(cfg.Sanitizer, delta)
    return writeOutput(cfg.Stdout, cfg.Format, cfg.Quiet, delta)
}

// After
func (r *runner) Run(ctx context.Context, cfg config) error {
    progress := ui.NewRuntime(r.Stdout, r.Stderr)
    progress.Quiet = r.Quiet
    ...
    delta = output.SanitizeObservationDelta(r.Sanitizer, delta)
    return writeOutput(r.Stdout, cfg.Format, r.Quiet, delta)
}
```

### 5. Update RunE call site

```go
// Before (cmd.go:56)
runner := newRunner(loadSnapshots)

// After
runner := newRunner(cmd, loadSnapshots)
```

## No Change Needed

### Tests

Existing tests (`diff_test.go`) test domain functions
(`ComputeObservationDelta`, `LatestTwoSnapshots`) and options
parsing (`buildFilter`, `parseChangeTypes`). None construct a
`runner` directly, so no test changes needed.

### output.go

`writeOutput` takes explicit parameters — its signature doesn't
change, just the source of values shifts from `cfg` to `r`.

### computeDelta

Already uses only `r.LoadSnapshots` and domain parameters from
config. No change needed.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/diff/run.go` | Move CLI fields to runner, expand `newRunner`, update `Run` |
| `cmd/enforce/diff/options.go` | Remove CLI concerns from `ToConfig` |
| `cmd/enforce/diff/cmd.go` | Pass `cmd` to `newRunner` |

## Acceptance

- `runner` holds CLI concerns (quiet, sanitizer, stdout, stderr)
- `config` holds only domain parameters (observations dir, format, filter)
- `newRunner(cmd, loader)` extracts global flags matching baseline/cidiff
- `--quiet` suppresses all output (text and JSON)
- `go vet ./cmd/enforce/diff/...` clean
- `make test` zero failures
