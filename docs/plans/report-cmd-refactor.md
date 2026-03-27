# Plan: Refactor cmd/diagnose/report/cmd.go

## Current State

The report command is well-structured — `Request` struct, embedded
template via `//go:embed`, format dispatch, Git audit. Two issues:

1. `Run` mixes git auditing (side effect) with rendering (logic)
2. `NewRunner` hardcodes `staveversion.String`

## Changes

### 1. Move git audit from Runner to RunE

Git auditing is a CLI concern (warns on stderr), not a report
generation concern. Move it to the RunE block so the Runner is
a pure data transformer.

```go
// Before (in Runner.Run)
if req.ProjectRoot != "" {
    gitInfo := compose.AuditGitStatus(req.ProjectRoot, req.AuditPaths)
    compose.WarnGitDirty(req.Stderr, gitInfo, "report", req.Quiet)
}

// After (in RunE, before Runner.Run)
if projectRoot != "" {
    gitInfo := compose.AuditGitStatus(projectRoot, auditPaths)
    compose.WarnGitDirty(cmd.ErrOrStderr(), gitInfo, "report", flags.Quiet)
}
return NewRunner(staveversion.String).Run(cmd.Context(), req)
```

### 2. Remove git metadata from Request

`ProjectRoot`, `AuditPaths`, `Stderr` are only used for git auditing.
With auditing moved to RunE, remove them from `Request`.

```go
// Before
type Request struct {
    InputFile    string
    TemplateFile string
    Format       ui.OutputFormat
    Quiet        bool
    Stdout       io.Writer
    Stderr       io.Writer        // REMOVE
    ProjectRoot  string           // REMOVE
    AuditPaths   []string         // REMOVE
}

// After
type Request struct {
    InputFile    string
    TemplateFile string
    Format       ui.OutputFormat
    Quiet        bool
    Stdout       io.Writer
}
```

### 3. Inject version into NewRunner

```go
// Before
func NewRunner() *Runner {
    return &Runner{Version: staveversion.String, ...}
}

// After
func NewRunner(version string) *Runner {
    return &Runner{Version: version, ...}
}
```

### 4. Use context in Run

Change `_ context.Context` to `ctx context.Context`. Even if not
threaded to render functions today, it prepares for future use.

## Files Changed

| File | Change |
|------|--------|
| `cmd/diagnose/report/cmd.go` | Move git audit to RunE, trim Request, inject version, use ctx |

## Acceptance

- `Runner.Run` does not call `compose.AuditGitStatus`
- `Request` has no `Stderr`, `ProjectRoot`, or `AuditPaths` fields
- `NewRunner` takes `version string` parameter
- `go test ./...` zero failures
- `make script-test` passes
