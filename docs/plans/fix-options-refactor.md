# Plan: Fix Options — Fail-Fast Validation

Add early validation for `--finding` format and `--input` file
existence in `PreRunE` so errors surface before heavy I/O.

## Changes

### 1. Validate --finding format in Prepare

**Problem**: The `<control_id>@<asset_id>` format isn't validated
until deep in `appfix.SelectFinding`, after the evaluation file has
been read and parsed. A malformed selector like `CTL.S3.PUBLIC.001`
(missing `@`) wastes I/O.

**Change**: Add format validation in `Prepare`. The `FindingRef`
stays as a string (the app layer uses it as-is via `FindingKey`),
but the `@` separator and non-empty parts are checked early.

```go
func (o *fixOptions) Prepare(_ *cobra.Command) error {
    o.InputPath = fsutil.CleanUserPath(o.InputPath)
    return o.validateFindingRef()
}

func (o *fixOptions) validateFindingRef() error {
    parts := strings.SplitN(o.FindingRef, "@", 2)
    if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
        return &ui.UserError{
            Err: fmt.Errorf(
                "invalid --finding %q: must be <control_id>@<asset_id>",
                o.FindingRef),
        }
    }
    return nil
}
```

### 2. Validate --input file exists in Prepare

**Problem**: If `--input` points to a non-existent file, the error
surfaces inside `appfix.Service.Fix` via `os.ReadFile`. Checking
in `Prepare` gives a cleaner error with a fix hint before any
processing starts.

**Change**: Add `os.Stat` check after path normalization.

```go
func (o *fixOptions) Prepare(_ *cobra.Command) error {
    o.InputPath = fsutil.CleanUserPath(o.InputPath)
    if _, err := os.Stat(o.InputPath); err != nil {
        return &ui.UserError{
            Err: fmt.Errorf("--input file %s: %w", o.InputPath, err),
        }
    }
    return o.validateFindingRef()
}
```

## No Change Needed

### Strongly typed IDs in Request

Splitting `FindingRef` into `kernel.ControlID` + `asset.ID` would
require changing `appfix.FixRequest`, `SelectFinding`, and
`FindingKey` — a cross-cutting app-layer change. The combined
`<control_id>@<asset_id>` string is the contract between CLI and
app layer. Validating the format early is sufficient.

### BindFlags

Already clean with `MarkFlagRequired` on both flags.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/fix/options.go` | Add `validateFindingRef`, file existence check in `Prepare` |

## Acceptance

- Malformed `--finding` (missing `@`, empty parts) fails in `PreRunE`
  with a `ui.UserError`
- Non-existent `--input` fails in `PreRunE` with path in message
- Both validations run before any file I/O
- `go vet ./cmd/enforce/fix/...` clean
- `make test` zero failures
