# Format-Dispatch TDA Debt — `switch opts.Format` Inventory

## Status

Open. Tracked as a separate technical-debt item — broader scope than the
incremental TDA batches landed across late April / early May 2026.

## Problem

29 command handlers branch on `opts.Format` to choose a rendering strategy.
Each site duplicates the same shape:

```go
switch opts.Format {
case "json":
    return renderJSON(out, result)
case "table":
    return renderTable(out, result)
case "markdown":
    return renderMarkdown(out, result)
default:
    return fmt.Errorf("unsupported format: %q", opts.Format)
}
```

The string is decided at parse time. The dispatch fires at the end of every
`RunE`. Adding a new format means editing 29 files; renaming `markdown` →
`md` means editing 29 files; tightening the unknown-format branch (some
sites return errors, some silently fall through to JSON) means auditing 29
sites for behavioural drift. This is exactly the duplicated-`if-else`
chain Tell-Don't-Ask exists to eliminate.

## Reference fix

`cmd/export/compliance/renderer.go` is the model:

- A `Renderer` interface with one method, `Render(w io.Writer, export any) error`.
- One concrete type per format (`JSONRenderer`, `TableRenderer`,
  `MarkdownRenderer`, `OSCALRenderer`).
- A factory `NewRenderer(format string, verbose bool) (Renderer, error)`
  that maps the string at parse time and returns the appropriate
  implementation. Unknown formats become an explicit error here, not at
  every call site.
- Each `RunE` constructs a renderer once and calls `Render` — the
  `switch` collapses to a single line.

The compliance command's two `RunE` paths (`run.go`, `composite.go`) both
route through `NewRenderer`. New formats add a case to the factory plus a
concrete type; nothing in the cmd-side handlers changes.

## Inventory

29 dispatch sites across the cmd/ tree (excluding the already-migrated
`cmd/export/compliance/`):

| File                                      | Line(s)        |
| ----------------------------------------- | -------------- |
| cmd/apply/run_newonly.go                  | 62             |
| cmd/budget/cmd.go                         | 169            |
| cmd/compare/cmd.go                        | 138            |
| cmd/consolidate/cmd.go                    | 207            |
| cmd/consolidate/diff.go                   | 46             |
| cmd/consolidate/history.go                | 66             |
| cmd/coverage/cmd.go                       | 120            |
| cmd/diagnose/explain_narrative.go         | 158            |
| cmd/enforce/graph/export_cmd.go           | 96             |
| cmd/expand/cmd.go                         | 146            |
| cmd/forensics/cmd.go                      | 123            |
| cmd/inventory/cmd.go                      | 82             |
| cmd/map/cmd.go                            | 101            |
| cmd/monitor/cmd.go                        | 133            |
| cmd/nep/principal.go                      | 123            |
| cmd/nep/resource.go                       | 116            |
| cmd/nep/summary.go                        | 145            |
| cmd/path/cmd.go                           | 163            |
| cmd/prune/inventory/run.go                | 136            |
| cmd/rank/cmd.go                           | 192, 215, 301  |
| cmd/report/cmd.go                         | 194            |
| cmd/simulate/cmd.go                       | 107            |
| cmd/snapshotdiff/cmd.go                   | 101, 139       |
| cmd/test/cmd.go                           | 127            |
| cmd/trend/run.go                          | 153            |
| cmd/verify/cmd.go                         | 127            |

## Remediation outline

1. Extract a shared `cmd/cmdutil/render.Renderer` interface mirroring the
   compliance shape but generic over the export type.
2. For each cmd package, add a `<pkg>/renderer.go` that defines the
   per-format implementations (re-using the existing `renderJSON` /
   `renderTable` / `renderMarkdown` helpers).
3. Replace the inline `switch` with a single `NewRenderer(opts.Format)`
   call at the start of `RunE`, dispatched once.
4. Unify the unknown-format behaviour across sites — currently some
   return `&ui.UserError{...}`, some return `fmt.Errorf`, some silently
   fall through to JSON. The factory should return a `ui.UserError` with
   a hint; each `RunE` propagates it directly.

## Why it is filed separately

This is not a single-PR refactor. Each command has its own renderer
helpers, its own export type, and (in some cases) its own custom
formats not present in the compliance set. Migrating in one batch
risks behavioural drift that the test suite will not catch (most
formatters lack golden tests). Plan: migrate two or three commands per
batch, with golden coverage added before each migration.
