# Format-Dispatch TDA Debt — `switch opts.Format` Inventory

## Status

**CLOSED 2026-05-18.** Zero pending dispatch sites. Every command
in `cmd/` that branches on `opts.Format` now goes through the
Renderer pattern.

Eleven migration batches (1 – 11) landed on 2026-05-18, closing the
inventory the same day it was last updated. The CLAUDE.md New
Command Checklist (item 7) enforces the pattern for future commands;
adding a new inline `switch opts.Format` should fail review.

Final tally:

- **32 files migrated** (the inventory listed 25 originally; +6 new
  files shipped after 2026-05-03 also migrated; +1 missed by the
  original switch-only grep — see batch 11 note).
- **35 dispatch sites** consolidated into factory calls.
- **One reference implementation** (`cmd/export/compliance/`) carried
  the pattern forward into 30+ new factories.

The remainder of this doc is preserved as a retrospective.

---

## Migration log (2026-05-03 → 2026-05-18)

- **Migrated (32 files, 35 sites)**: `cmd/inventory/cmd.go` (≤2026-05-18),
  `cmd/verify/cmd.go` (2026-05-18, batch 1),
  `cmd/budget/cmd.go` (2026-05-18, batch 1),
  `cmd/compare/cmd.go` (2026-05-18, batch 2),
  `cmd/simulate/cmd.go` (2026-05-18, batch 2),
  `cmd/test/cmd.go` (2026-05-18, batch 2),
  `cmd/coverage/cmd.go` (2026-05-18, batch 3),
  `cmd/expand/cmd.go` (2026-05-18, batch 3),
  `cmd/forensics/cmd.go` (2026-05-18, batch 3),
  `cmd/readiness/cmd.go` (2026-05-18, batch 4),
  `cmd/gaps/cmd.go` (2026-05-18, batch 4),
  `cmd/contract/cmd.go` (2026-05-18, batch 4),
  `cmd/validatemapping/cmd.go` (2026-05-18, batch 5),
  `cmd/catalog/cmd.go` (2026-05-18, batch 5),
  `cmd/search/cmd.go` (2026-05-18, batch 5),
  `cmd/apply/run_newonly.go` (2026-05-18, batch 6),
  `cmd/diagnose/explain_narrative.go` (2026-05-18, batch 6),
  `cmd/enforce/graph/export_cmd.go` (2026-05-18, batch 6),
  `cmd/map/cmd.go` (2026-05-18, batch 7),
  `cmd/path/cmd.go` (2026-05-18, batch 7),
  `cmd/monitor/cmd.go` (2026-05-18, batch 7),
  `cmd/prune/inventory/run.go` (2026-05-18, batch 8),
  `cmd/report/cmd.go` (2026-05-18, batch 8),
  `cmd/trend/run.go` (2026-05-18, batch 8),
  `cmd/consolidate/cmd.go` (2026-05-18, batch 9),
  `cmd/consolidate/diff.go` (2026-05-18, batch 9),
  `cmd/consolidate/history.go` (2026-05-18, batch 9),
  `cmd/nep/principal.go` (2026-05-18, batch 10),
  `cmd/nep/resource.go` (2026-05-18, batch 10),
  `cmd/nep/summary.go` (2026-05-18, batch 10),
  `cmd/rank/cmd.go` (2026-05-18, batch 11 — 4 sites incl. one missed
  by the original switch-only grep),
  `cmd/snapshotdiff/cmd.go` (2026-05-18, batch 12 — closes the
  inventory).
- **All post-2026-05-03 commands** (validatemapping, readiness, contract,
  gaps, catalog, search) are migrated. Every command shipped after
  the original doc inherits the Renderer pattern.
- **All multi-site clusters are migrated** (consolidate, nep, rank,
  snapshotdiff).
- **Currently pending**: 0 sites. Inventory closed.

**2026-05-18 mitigations**:
1. New Command Checklist in `CLAUDE.md` mandates the Renderer pattern
   for every new command and forbids adding to this inventory.
2. Batches 1 + 2 migrated five commands (`verify`, `budget`, `compare`,
   `simulate`, `test`) and established the per-package Renderer
   convention (`cmd/<pkg>/renderer.go` with one `Renderer` interface,
   one type per format, one `NewRenderer` factory, and a
   `renderer_test.go` covering the format map + unknown-format error +
   smoke output).
3. The convention tolerates per-package interface shapes — `simulate`'s
   `TextRenderer` carries the input fix list because the header names
   it; `test`'s `TableRenderer` carries Verbose; `test`'s Render method
   takes `(results, summary)` instead of one payload. The shared
   property is "factory + concrete types + tests"; the precise interface
   shape is whatever each package actually renders.

## Problem (historical — preserved for retrospective context)

At the time this doc was filed, 29 command handlers in `cmd/`
branched on `opts.Format` to choose a rendering strategy. Each site
duplicated the same shape:

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

**Zero pending sites.** Inventory closed 2026-05-18 with batch 12.
The full per-file migration log is below.

### Migrated

| File                       | Migrated on   | Notes                                                                    |
| -------------------------- | ------------- | ------------------------------------------------------------------------ |
| cmd/inventory/cmd.go       | (≤2026-05-18) | No longer carries a switch-on-Format.                                    |
| cmd/verify/cmd.go          | 2026-05-18    | Batch 1. `cmd/verify/renderer.go` + `renderer_test.go`. 3 formats (table/json/markdown). |
| cmd/budget/cmd.go          | 2026-05-18    | Batch 1. `cmd/budget/renderer.go` + `renderer_test.go`. 4 formats (table/json/openmetrics/markdown). |
| cmd/compare/cmd.go         | 2026-05-18    | Batch 2. `cmd/compare/renderer.go` + `renderer_test.go`. 3 formats (table/json/markdown). |
| cmd/simulate/cmd.go        | 2026-05-18    | Batch 2. `cmd/simulate/renderer.go` + `renderer_test.go`. 2 formats (text/json). Extracted `writeText` helper from inline `fmt.Fprintf`; `TextRenderer` carries the input fix list because the header names it. |
| cmd/test/cmd.go            | 2026-05-18    | Batch 2. `cmd/test/renderer.go` + `renderer_test.go`. 3 formats (table/json/tap). `Render` takes `(results, summary)` together; `TableRenderer` carries Verbose. |
| cmd/coverage/cmd.go        | 2026-05-18    | Batch 3. `cmd/coverage/renderer.go` + `renderer_test.go`. 2 formats (table/json). |
| cmd/expand/cmd.go          | 2026-05-18    | Batch 3. `cmd/expand/renderer.go` + `renderer_test.go`. 2 formats (text/json). Introduces a `Payload` struct so the Renderer interface stays single-arg even though renderJSON/renderText each take 4 inputs. |
| cmd/forensics/cmd.go       | 2026-05-18    | Batch 3. `cmd/forensics/renderer.go` + `renderer_test.go`. 2 formats (table/json). |
| cmd/readiness/cmd.go       | 2026-05-18    | Batch 4. `cmd/readiness/renderer.go` + `renderer_test.go`. 2 formats (text/json). Collapsed the validation switch + dispatch switch into one NewRenderer call at the top of run(). |
| cmd/gaps/cmd.go            | 2026-05-18    | Batch 4. `cmd/gaps/renderer.go` + `renderer_test.go`. 2 formats (text/json). Same dual-switch collapse as readiness; TextRenderer carries TopN. |
| cmd/contract/cmd.go        | 2026-05-18    | Batch 4. `cmd/contract/renderer.go` + `renderer_test.go`. 2 formats (text/json). Renderer.Render takes `any` because contract has two payload types (typeReport, listReport); TextRenderer type-switches like cmd/export/compliance does. Three dispatch sites (1 validation switch + 2 if-statements in runReport/runList) collapsed into one renderer threaded through. |
| cmd/validatemapping/cmd.go | 2026-05-18    | Batch 5. `cmd/validatemapping/renderer.go` + `renderer_test.go`. 2 formats (text/json). Straightforward — Renderer takes the existing `report` struct. |
| cmd/catalog/cmd.go         | 2026-05-18    | Batch 5. `cmd/catalog/renderer.go` + `renderer_test.go`. 2 formats (text/json). Extracted the inline anonymous JSON struct as a named `catalogReport` type so the JSON contract is grep-able. |
| cmd/search/cmd.go          | 2026-05-18    | Batch 5. `cmd/search/renderer.go` + `renderer_test.go`. 2 formats (text/json). Same anonymous-struct extraction as catalog — JSON shape is now a named `searchReport` type. |
| cmd/apply/run_newonly.go   | 2026-05-18    | Batch 6. `cmd/apply/renderer_newonly.go` + `renderer_newonly_test.go`. 2 formats (text/json). Uses a `NewOnlyRenderer` interface (prefixed name) because cmd/apply owns multiple output surfaces and future migrations will add more renderers in this package. |
| cmd/diagnose/explain_narrative.go | 2026-05-18 | Batch 6. `cmd/diagnose/renderer_explain_narrative.go` + test. 3 formats (narrative/json/markdown). JSONRenderer preserves the single-playbook-emits-object special case from the pre-migration switch; MarkdownRenderer and TextRenderer carry the Depth flag. Prefixed-name `ExplainNarrativeRenderer` for the same multi-surface reason as cmd/apply. |
| cmd/enforce/graph/export_cmd.go | 2026-05-18 | Batch 6. `cmd/enforce/graph/renderer.go` + `renderer_test.go`. 4 formats (json/stix/jsonld/graphml). All concrete renderers delegate to existing graphpkg helpers; default branch (was JSON fallback) becomes the explicit `"json"`/`""` case. |
| cmd/map/cmd.go             | 2026-05-18    | Batch 7. `cmd/map/renderer.go` + `renderer_test.go`. 4 formats (table/json/navigator/markdown). NavigatorRenderer encodes a different JSON projection (`appcoverage.NavigatorLayer`) so it's distinct from JSONRenderer even though both produce JSON. |
| cmd/path/cmd.go            | 2026-05-18    | Batch 7. `cmd/path/renderer.go` + `renderer_test.go`. 3 formats (json/dot/csv-edges). No default human-readable format — the empty string is invalid here, preserving the pre-migration semantics. |
| cmd/monitor/cmd.go         | 2026-05-18    | Batch 7. `cmd/monitor/renderer.go` + `renderer_test.go`. 3 formats (json/plain/live). Wider Renderer interface — `Render(ctx, w, opts, loadState)` — because the `live` mode is a long-running poll loop, not a one-shot render. JSON/Plain ignore ctx and opts; LiveRenderer uses them. Documents the trade-off: explicit interface width is the cost of fitting structurally different modes into one dispatch table. |
| cmd/prune/inventory/run.go | 2026-05-18    | Batch 8. `cmd/prune/inventory/renderer.go` + `renderer_test.go`. 3 formats (table/json/openmetrics). Straightforward delegation to existing renderInventoryJSON/OpenMetrics/Table helpers. |
| cmd/report/cmd.go          | 2026-05-18    | Batch 8. `cmd/report/renderer.go` + `renderer_test.go`. 2 formats (json/markdown). Factory takes `contracts.OutputFormat` directly (the only typed-enum factory in the codebase) because the executive report command was already using the typed enum for --format. Empty string maps to JSON to preserve pre-migration default. |
| cmd/trend/run.go           | 2026-05-18    | Batch 8. `cmd/trend/renderer.go` + `renderer_test.go`. 4 formats (table/json/openmetrics/executive-summary). |
| cmd/consolidate/{cmd,diff,history}.go | 2026-05-18 | Batch 9. `cmd/consolidate/renderer.go` + `renderer_test.go`. First multi-site cluster — three sibling files of one command all use `opts.Format` but render different payload types (ConsolidatedReport / OutlierReport / OrgTrendReport). One renderer.go declares three Renderer interfaces (`ConsolidatedRenderer`, `DiffRenderer`, `HistoryRenderer`) with three factories, each call site invokes its own. Formats: consolidate is table/json, diff is table/json, history is table/json/markdown. |
| cmd/nep/{principal,resource,summary}.go | 2026-05-18 | Batch 10. `cmd/nep/renderer.go` + `renderer_test.go`. Same multi-site shape as consolidate — three sibling files, three Renderer interfaces (`PrincipalRenderer`, `ResourceRenderer`, `SummaryRenderer`). `ResourceRenderer` uses a `ResourcePayload` struct because the DOT renderer needs unfiltered entries while JSON/Table use the filtered view. Formats: principal is table/json, resource is table/json/dot, summary is table/json. |
| cmd/rank/cmd.go (4 sites) | 2026-05-18 | Batch 11. `cmd/rank/renderer.go` + `renderer_test.go`. Different shape from prior batches: the concrete formatters already lived in `internal/app/rank/formatter/` (RoadmapFormatter, SprintFormatter, IdentityRankingFormatter interfaces + JSON/CSV/TextRoadmap/TextSprint/TextIdentityRanking concretes). Batch 11 added the missing concretes (`JSONSprint`, `JSONIdentityRanking`, `TeamRoadmapsFormatter` interface + `JSONTeamRoadmaps` + `TextTeamRoadmaps`) and four factory functions in cmd/rank/renderer.go. Four dispatch sites (three switches + one `if format == "json"` the original switch-only grep missed) collapse into factory calls. |
| cmd/snapshotdiff/cmd.go (2 sites) | 2026-05-18 | Batch 12 — closes the inventory. `cmd/snapshotdiff/renderer.go` + `renderer_test.go`. Two payload types under one command: catalog diff (`appdiff.Delta`) and snapshot diff (`snapshotdiff.DiffResult`). Two Renderer interfaces (`CatalogRenderer`, `SnapshotRenderer`) with two factories. Same multi-payload recipe as cmd/consolidate and cmd/nep, just within a single file rather than sibling files. |

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
