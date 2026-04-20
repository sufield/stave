# Cobra-decoupling audit

**Date**: 2026-04-20
**Scope**: Residual `*cobra.Command` coupling inside command `RunE`
closures and their helpers, enumerated for staged removal.

## Why this matters

The architecture boundary doc (`docs/design/architecture-boundary.md`)
names `pkg/stave/` as the Go library surface and records the
refactor-on-touch policy for migrating library-suitable CLI
commands onto it. That policy works cleanly only when the adapter
layer is actually cobra-free below its RunE closure — otherwise,
a "route through pkg/stave" migration becomes a rewrite rather
than a translation, because the run function can't be lifted
without also lifting a cobra dependency.

Previously audited surface: 29 instances across 11 files,
grouped into five categories. This document tracks them to
closure.

## Categories

1. **`cmd.Flags().Changed()` used inside RunE.** Capture belongs
   in PreRunE on the Options struct; RunE reads the field.
2. **Helpers that take `*cobra.Command` when they should take
   primitives.** The hard case is helpers that propagate cobra
   into otherwise-pure logic.
3. **Inline `fmt.Fprintf` rendering in RunE.** Move to a
   dedicated renderer that takes `io.Writer`.
4. **Uncontrolled long RunE bodies.** Extract into a run
   function that takes an Input struct.
5. **Whole-subsystem lack of the PreRunE pattern.** The
   `cmd/exempt` tree in particular inlines flag-reading into
   RunE across every subcommand.

## Tally

| Category | Count | Status |
|---|---:|---|
| 1 — `Changed()` in RunE | 3 | Resolved 2026-04-20 |
| 2 — helpers taking `*cobra.Command` | 8 | Resolved 2026-04-20 |
| 3 — inline `fmt.Fprintf` rendering | 8 | Resolved 2026-04-20 |
| 4 — uncontrolled long RunE | 1 | Resolved 2026-04-20 |
| 5 — `cmd/exempt` subsystem | 9 | Resolved 2026-04-20 |
| **Total** | **29** | **29 of 29 resolved** |

**Debt closed.** Every CLI command's RunE is structurally
separable from cobra: Options struct + Normalize() + runner +
renderer, with cobra references limited to flag binding and the
thin RunE closure. The refactor-on-touch policy
(architecture-boundary.md) now has clean ground across the
entire codebase — subsequent iterations that route
library-suitable commands through `pkg/stave/` no longer need
cobra-decoupling as a prerequisite.

## Resolved instances (this iteration)

### Category 1 — `Changed()` in RunE

| File | Line | Flag | Fix |
|---|---:|---|---|
| `cmd/enforce/diff/cmd.go` | 52 | `format` | Dropped `formatChanged` arg from `toConfig`; after helper refactor, the bool was no longer consulted. |
| `cmd/enforce/status/cmd.go` | 45 | `format` | Dropped `FormatChanged` from `cmdIO` struct; field became dead after helper refactor. |
| `cmd/diagnose/finding_cmd.go` | 93–98 | `controls`, `observations`, `format` | Captures moved to PreRunE onto local vars; RunE reads the captured bools. |

### Category 2 — helpers taking `*cobra.Command`

Single helper simplification — `compose.ResolveFormatValue(cmd, raw)`
→ `compose.ResolveFormatValue(raw)`. The helper's `cmd` parameter
was vestigial: it passed through to `cliflags.ResolveFormat(cmd,
raw)` which ignored `cmd` and just called `strings.TrimSpace`.

Ripples:
- `cliflags.ResolveFormat` and `cliflags.ResolveFormatPure`
  deleted (both were `TrimSpace` wrappers with unused
  parameters; only compose referenced them).
- `compose.ResolveFormatValuePure` deleted (identical to
  `ResolveFormatValue` after its `formatChanged` / `isJSONMode`
  bools were confirmed unused). The 5 `ResolveFormatValuePure`
  callers migrated to `ResolveFormatValue`.
- 24 call sites of `compose.ResolveFormatValue(cmd, ...)`
  updated to drop the `cmd` argument.
- `(*options).resolveFormat(cmd)` in
  `cmd/diagnose/report/options.go` simplified to
  `(*options).resolveFormat()`.

Originally 8 category-2 instances were called out at specific
line numbers; the helper refactor closed all of them plus the 16
additional callers the brief did not enumerate. The fix scope
was determined by the helper's signature change.

### Category 3 — inline `fmt.Fprintf` rendering (resolved)

All 8 in `cmd/exempt/`. Each subcommand's RunE now delegates
rendering to a typed `render<Name>(w io.Writer, result T) error`
function. The writer is resolved once at the RunE boundary via
`cmd.OutOrStdout()`; the renderer sees only a plain writer and
the typed result.

### Category 4 — uncontrolled long RunE (resolved)

`cmd/commands.go:newSnapshotQueryCmd` (the 65-line RunE) was
decomposed into the standard PreRunE/Options/Run/Render shape
at `cmd/prune/snapshot/`:

- `query_cmd.go` — `NewQueryCmd()` constructor; thin RunE that
  calls `runQuery` then `renderQuery`
- `query_options.go` — `queryOptions` struct with `Normalize()`
  called from PreRunE (resolves dir default, parses `--now`,
  `--older-than`, `--newer-than`)
- `query_run.go` — `runQuery(opts) (queryResult, error)`; pure
  logic, no cobra
- `query_output.go` — `renderQuery(w, result, format)` plus
  health/listing text variants; takes `io.Writer`

`cmd/commands.go` lost its 100-line closure (plus five now-dead
imports); `cmd/prune/commands.go` adds `snapshot.NewQueryCmd()`
alongside the existing plan/quality siblings.

Byte-identical output verified on 4 flag variants (default, JSON,
health, empty-result) via stash/diff.

### Category 5 — `cmd/exempt` subsystem (resolved)

All 10 cmd/exempt subcommands (`acknowledge`, `except`, `asset`,
`list`, `remove`, `upcoming`, `history`, `validate`, `export`,
`suggest`) now follow the standard command shape:

- `<name>Options` struct with flag-bound fields
- `Normalize()` method called from `PreRunE`
- `run<Name>(opts)` returning a typed result or plain error
- `render<Name>(w, result)` taking `io.Writer`
- Thin `RunE` that invokes runner then renderer

Side effects (YAML acceptance-file writes, POAM file writes)
happen in runners, not renderers. Error messages and YAML
contents verified byte-identical pre/post by stash/diff on the
`acknowledge → list → list --format json → history → upcoming
→ validate → remove` workflow; e2e suite passes.

## Iteration closure

The cobra-decoupling debt audit is closed. This document
remains as the record of how the structural fix was applied.
Future discoveries of cobra contamination in new commands
should follow the same shape documented in the resolved
instances above.
