# Plan: Refactor cmd/diagnose/artifacts/controls_cmd.go

## Problem

The `controls list` command mixes CLI concerns with business logic:

1. **Source selection in cmd layer**: `listControlRows` contains a 30-line
   `if cfg.UseBuiltIn` branch with registry construction, selector
   parsing, and filtering. This belongs in the app layer.

2. **Hardcoded default path**: `"controls/s3"` is duplicated in 10 files
   as a flag default. Should be a single constant.

3. **Non-standard writer type**: `runListPacks` uses
   `interface{ Write([]byte) (int, error) }` instead of `io.Writer`.

4. **Format string comparison**: `strings.ToLower(cfg.Format) == "json"`
   bypasses the existing `ui.OutputFormat` type.

## Changes

### 1. Extract ControlProvider interface into catalog package

Move the "where do controls come from?" decision out of the cmd layer.

**New file: `internal/app/catalog/provider.go`**

```go
// ControlProvider loads controls from any source.
type ControlProvider interface {
    Load(ctx context.Context) ([]policy.ControlDefinition, error)
}

// NewProvider selects the right provider based on config.
func NewProvider(cfg ListConfig, filters []string, fsRepo appcontracts.ControlRepository) ControlProvider {
    if cfg.UseBuiltIn {
        return &builtInProvider{filters: filters}
    }
    return &fsProvider{repo: fsRepo, dir: cfg.Dir}
}
```

**`builtInProvider`** — wraps `builtin.Registry` with filter parsing:

```go
type builtInProvider struct {
    filters []string
}

func (p *builtInProvider) Load(ctx context.Context) ([]policy.ControlDefinition, error) {
    registry := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded",
        builtin.WithAliasResolver(predicate.ResolverFunc()))
    if len(p.filters) > 0 {
        selectors, err := parseSelectors(p.filters)
        if err != nil { return nil, err }
        return registry.Filtered(selectors)
    }
    return registry.All()
}
```

**`fsProvider`** — wraps the existing repo:

```go
type fsProvider struct {
    repo appcontracts.ControlRepository
    dir  string
}

func (p *fsProvider) Load(ctx context.Context) ([]policy.ControlDefinition, error) {
    return p.repo.LoadControls(ctx, strings.TrimSpace(p.dir))
}
```

### 2. Update ListRunner to use ControlProvider

```go
// Before
type ListRunner struct {
    Repo appcontracts.ControlRepository
}
func (r *ListRunner) Run(ctx context.Context, cfg ListConfig) ([]ControlRow, error) {
    controls, err := r.Repo.LoadControls(ctx, cfg.Dir)

// After
type ListRunner struct {
    Provider ControlProvider
}
func (r *ListRunner) Run(ctx context.Context, cfg ListConfig) ([]ControlRow, error) {
    controls, err := r.Provider.Load(ctx)
```

### 3. Thin the command's RunE

```go
// Before (30 lines in listControlRows)
func listControlRows(ctx, newCtlRepo, cfg, filterPatterns) {
    if cfg.UseBuiltIn {
        registry := builtin.NewRegistry(...)
        // 20 lines of selector parsing, filtering, sorting
    }
    repo, err := newCtlRepo()
    return (&catalog.ListRunner{Repo: repo}).Run(ctx, cfg)
}

// After (5 lines)
RunE: func(cmd *cobra.Command, _ []string) error {
    repo, _ := newCtlRepo()  // nil if UseBuiltIn
    provider := catalog.NewProvider(cfg, filterPatterns, repo)
    runner := &catalog.ListRunner{Provider: provider}
    rows, err := runner.Run(cmd.Context(), cfg)
    if err != nil { return err }
    return appartifacts.FormatControlOutput(stdout, cfg, rows)
}
```

### 4. Extract default controls path constant

**New in `cmd/cmdutil/cliflags/defaults.go`:**

```go
const DefaultControlsDir = "controls/s3"
```

Replace all 10 hardcoded `"controls/s3"` references.

### 5. Fix writer type and format comparison

**`runListPacks`**: `interface{ Write([]byte) (int, error) }` → `io.Writer`

**Format check**: `strings.ToLower(cfg.Format) == "json"` → use
`ui.OutputFormat` type or at minimum `cfg.Format == "json"` (already
lowercase from flag default).

## Files Changed

| File | Change |
|------|--------|
| `internal/app/catalog/provider.go` | New: ControlProvider + builtInProvider + fsProvider |
| `internal/app/catalog/list.go` | ListRunner takes ControlProvider instead of Repo |
| `internal/app/catalog/list_test.go` | Update test to use provider |
| `cmd/diagnose/artifacts/controls_cmd.go` | Thin RunE, delete listControlRows, fix writer type |
| `cmd/cmdutil/cliflags/defaults.go` | New: DefaultControlsDir constant |
| 10 files with `"controls/s3"` | Use `cliflags.DefaultControlsDir` |

## What NOT to Change

- **aliases and alias-explain commands**: Already thin (3-5 lines each).
  No business logic to extract.
- **explain command**: Already delegates to `diagnose.NewExplainer`.
- **packs list/show**: Already delegates to `artifacts.NewPackRunner`.

## Acceptance

- `listControlRows` deleted from `controls_cmd.go`
- `controls_cmd.go` RunE functions are under 10 lines each
- No `builtin.Registry` or `builtin.Selector` imports in cmd layer
- `"controls/s3"` appears in exactly 1 place (the constant)
- `go build ./...` clean
- `go test ./...` zero failures
- `make clig-check` passes
- `make script-test` passes
