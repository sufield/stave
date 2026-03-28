# Plan: Graph Options — Naming Consistency and Defaults Constructor

Rename abbreviated fields, drop `Raw` suffixes, and extract defaults
into a constructor — matching the pattern applied to gate options.

## Changes

### 1. Rename fields for consistency

| Before | After | Rationale |
|--------|-------|-----------|
| `ObsDir` | `ObservationsDir` | Matches `--observations` flag name |
| `FormatRaw` | `Format` | Raw suffix redundant in options struct |

All references in `BindFlags` and `ToConfig` updated.

### 2. Extract defaultCoverageOptions constructor

**Problem**: Defaults are defined as an inline struct literal in
`cmd.go:26-30`. Extracting into a constructor matches the gate
(`DefaultOptions`) and diff (`DefaultOptions`) pattern and makes
defaults visible from the options file.

```go
func defaultCoverageOptions() coverageOptions {
    return coverageOptions{
        ControlsDir:     cliflags.DefaultControlsDir,
        ObservationsDir: "observations",
        Format:          "dot",
    }
}
```

`cmd.go` becomes:

```go
opts := defaultCoverageOptions()
```

(Pointer taken at `BindFlags` call — `opts.BindFlags(cmd)` works
on value receiver if methods use pointer, so use `&opts` or keep
pointer semantics.)

## No Change Needed

### ToConfig

Already implemented in previous commit with format parsing, path
cleaning, and error wrapping.

### BindFlags

Already includes completion registration. No change beyond field
renames.

## Files Changed

| File | Change |
|------|--------|
| `cmd/enforce/graph/options.go` | Rename fields, add `defaultCoverageOptions` |
| `cmd/enforce/graph/cmd.go` | Use `defaultCoverageOptions()` instead of inline literal |

## Acceptance

- Field names match flag names (no abbreviations or Raw suffixes)
- Defaults defined in `defaultCoverageOptions` constructor
- `cmd.go` inline struct literal replaced
- `go vet ./cmd/enforce/graph/...` clean
- `make test` zero failures
