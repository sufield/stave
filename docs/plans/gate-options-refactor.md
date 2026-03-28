# Plan: Gate Options — Naming, Error Wrapping, and Nil Safety

Improve field naming for readability, wrap bare errors in `ToConfig`,
and guard against nil evaluator in config default resolution.

## Changes

### 1. Rename abbreviated and Raw-suffixed fields

**Problem**: `BasePath`, `CtlDir`, `ObsDir` use abbreviations that
don't match flag names. `PolicyRaw`, `NowRaw`, `FormatRaw` carry
`Raw` suffixes that are redundant in an options struct (all values
are raw until `ToConfig` is called).

**Change**: Rename for consistency with flag names and other packages.

| Before | After | Flag |
|--------|-------|------|
| `PolicyRaw` | `Policy` | `--policy` |
| `BasePath` | `BaselinePath` | `--baseline` |
| `CtlDir` | `ControlsDir` | `--controls` |
| `ObsDir` | `ObservationsDir` | `--observations` |
| `NowRaw` | `Now` | `--now` |
| `FormatRaw` | `Format` | `--format` |

All references in `BindFlags`, `resolveConfigDefaults`, and
`ToConfig` updated accordingly.

### 2. Wrap bare errors in ToConfig

**Problem**: `ParseGatePolicy` and `PrepareEvaluationContext` errors
are returned directly. In CI logs, the error appears without context
about which stage of gate configuration failed.

```go
// Before
policy, err := appconfig.ParseGatePolicy(o.PolicyRaw)
if err != nil {
    return config{}, err
}

// After
policy, err := appconfig.ParseGatePolicy(o.Policy)
if err != nil {
    return config{}, fmt.Errorf("invalid policy: %w", err)
}
```

Both error returns wrapped:

| Call | Wrap message |
|------|-------------|
| `ParseGatePolicy` | `"invalid policy: %w"` |
| `PrepareEvaluationContext` | `"prepare evaluation context: %w"` |

### 3. Nil guard in resolveConfigDefaults

**Problem**: `EvaluatorFromCmd` returns nil when no project config is
loaded (e.g. `--help`). Calling `eval.CIFailurePolicy()` on nil
panics. Same latent bug fixed in fix-loop.

```go
// Before
func (o *gateOptions) resolveConfigDefaults(cmd *cobra.Command) {
    eval := cmdctx.EvaluatorFromCmd(cmd)
    if !cmd.Flags().Changed("policy") {
        o.PolicyRaw = string(eval.CIFailurePolicy())
    }

// After
func (o *gateOptions) resolveConfigDefaults(cmd *cobra.Command) {
    eval := cmdctx.EvaluatorFromCmd(cmd)
    if eval == nil {
        return
    }
    if !cmd.Flags().Changed("policy") {
        o.Policy = string(eval.CIFailurePolicy())
    }
```

## No Change Needed

### Struct naming (gateOptions)

Unexported type, internal to the package. Renaming to `Options` and
exporting would be inconsistent with `fixOptions` and `loopOptions`
in the sibling fix package. Keep as-is.

### Lifecycle (Prepare/resolveConfigDefaults)

The `Prepare` → `resolveConfigDefaults` → `normalize` pattern is
used across fix-loop, diff, and gate. Renaming to
`ValidateAndComplete` in just one package would break consistency.

### Pointer returns

`gateOptions` and `config` are small structs. Value semantics work
fine and avoid nil-check overhead at call sites.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/gate/options.go` | Rename fields, wrap errors, add nil guard |

## Acceptance

- Field names match flag names (no abbreviations or Raw suffixes)
- All `ToConfig` errors wrapped with `%w` and context
- Nil evaluator doesn't panic in `resolveConfigDefaults`
- `go vet ./cmd/enforce/gate/...` clean
- `make test` zero failures
