# Architecture Boundary: Shared Core vs. Adapter Layers

**Date**: 2026-04-20
**Purpose**: Name the packages that constitute Stave's shared
evaluation core and the rule for keeping CLI and library adapter
layers from forking it. Referenced by the refactor-on-touch
policy (see end of this document).

## Premise

Stave has two programmatic entry points into evaluation:

- **CLI** (`cmd/apply/`): users invoke `./stave apply` on the
  command line. Adapter code reads flags, wires observation /
  control repositories, calls the evaluation workflow, and
  renders output in text / JSON / SARIF.
- **Library** (`pkg/stave/`): Go consumers call
  `stave.Apply(ctx, Config)` and receive a typed `*Assessment`
  without shelling out. Adapter code wires default factories,
  translates `Config` into internal request types, and converts
  the internal report into the library's typed result shape.

Both paths reach the same evaluation engine. The question this
document answers: **what prevents them from drifting?**

## The boundary, in packages

Everything in the table below is **shared core**. Both
`cmd/apply/` and `pkg/stave/` import from these packages. Neither
may re-implement logic that lives inside them; the Go `internal/`
rule enforces the "internal" half, and convention (plus code
review) enforces the "don't duplicate" half.

### Shared core — evaluation engine

| Package | Role |
|---|---|
| `internal/app/eval` | `AuditWorkflow`, `PerformAssessment`, `BuildDependencies`, `AssessmentConfig`, `ApplyDeps`, `Enrich`. The canonical orchestration layer. Both paths construct `*AuditWorkflow` and call `PerformAssessment`. |
| `internal/core/evaluation` | `ComplianceReport`, `Finding`, `Issue`, `MatchedClause`, `RunInfo`, `ComplianceSummary`, `SecurityState`, `SortFindings`, `StableFindingID`, `BuildIssues`, SLA annotation. |
| `internal/core/evaluation/engine` | Predicate evaluation, assessor. Called from `evaluate_workflow.go`. |
| `internal/core/evaluation/risk` | Chain detection, attack-stage summary, exposure ranking, score breakdown. |
| `internal/core/evaluation/remediation` | Finding enrichment (spec + plan resolution). |
| `internal/core/evaluation/coverage` | Per-tool, per-domain coverage aggregation. |
| `internal/core/controldef` | `ControlDefinition`, `Severity`, `Classification`, `UnsafePredicate`, `ChainDefinition`, `Alternative`. |
| `internal/core/asset` | `Asset`, `Snapshot`, `ID`, `ExposureLifecycle`. |
| `internal/core/kernel` | Typed primitives (`ControlID`, `AssetType`, `ScopeTag`, `Duration`, etc.). |
| `internal/core/ports` | `Clock`, `Digester`, `Tracer` — interfaces the core requires. |
| `internal/core/predicate` | Field-path parsing, operator vocabulary. |

### Shared core — adapters the engine needs

| Package | Role |
|---|---|
| `internal/adapters/controls/builtin` | Loads the embedded builtin control catalog. |
| `internal/adapters/controls/yaml` | Parses control YAML from a directory. |
| `internal/adapters/observations` | Loads observation snapshots from a directory or stdin. |
| `internal/adapters/coverage` | Loads embedded alternative-tool inventories. |
| `internal/builtin/predicate` | Resolves named predicate aliases. |
| `internal/cel` | CEL-based predicate evaluator. |
| `internal/platform/crypto` | Content hasher used by the engine for input fingerprints. |

### Shared core — boundary types

| Package | Role |
|---|---|
| `internal/app/contracts` | Port interfaces (`ObservationRepository`, `ControlRepository`, `FindingMarshaler`) and boundary types (`EnrichedResult`). |
| `internal/core/usecase` | `ApplyRequest`, `ApplyResponse`, `EvaluationRunnerPort`. The canonical application-layer entry point; the library is currently the only production consumer. |
| `internal/core/report` | `Assessment` JSON wire shape (`out.v0.1`). |

### CLI-only adapter packages

`cmd/apply/` additionally reaches into CLI-specific adapters that
the library does not use: SLA overlay (`internal/adapters/sla`,
`internal/app/exemptlapse`), team routing (`internal/app/teams`),
readiness (`internal/app/readiness`), staleness
(`internal/app/staleness`), reachability
(`internal/app/reachability`), finding filtering
(`internal/app/findingfilter`), the pack system
(`internal/builtin/pack`), exemption / acknowledgment adapters,
telemetry, diagnostics (`internal/core/diag`), outcome
classification (`internal/core/outcome`), sanitization, plus the
`cmd/cmdutil/*` tree (flag parsing, compose factories,
`cliflags`, `cmdctx`, `projctx`).

### Library-only adapter package

`pkg/stave/` only: `pkg/stave/` itself. It currently routes
through `usecase.Apply` with a production adapter that wraps
`appeval.AuditWorkflow` — the first and only production consumer
of `EvaluationRunnerPort`. Everything below that adapter is
shared core.

## What prevents drift

1. **Go's `internal/` rule.** External consumers cannot import
   anything under `internal/`. Neither `cmd/` nor `pkg/stave/`
   can expose internal types to third parties, so no drift path
   runs through third-party code.
2. **Both paths import `internal/app/eval`.**
   `cmd/apply/deps.go:149` calls `appeval.BuildDependencies`;
   `pkg/stave/apply.go:99` constructs `&appeval.AuditWorkflow{}`
   directly. Both call `PerformAssessment` on the same workflow
   type. A behavior fix in `workflow.go` reaches both paths at
   compile time.
3. **No evaluation logic in adapter layers.** `cmd/apply/*` and
   `pkg/stave/*` contain flag parsing, dependency wiring,
   output rendering, and type conversion — no predicate
   evaluation, no scoring, no chain detection, no finding
   construction. Those live under `internal/core/evaluation/`
   and `internal/app/eval/`. Code review is the current
   mechanism that catches new logic landing in the wrong layer.

The compiler cannot prove (3) — a future contributor could, in
principle, add `pkg/stave/myeval.go` that bypasses `AuditWorkflow`.
This document is the reference for why that would be wrong.

## The rule

**Core evaluation logic lives in `internal/core/evaluation/` or
`internal/app/eval/`. CLI adapter code in `cmd/`. Library adapter
code in `pkg/stave/`. Adapter layers do flag parsing, dependency
wiring, output rendering, and type conversion — nothing else.**

When in doubt, ask: *if I changed this code, would both the CLI
and library be affected?* If yes, it belongs under `internal/`.
If it's CLI-flag-specific or library-typed-result-specific, it
belongs in the respective adapter.

## Refactor-on-touch policy

`cmd/apply/` currently calls `appeval.BuildDependencies` directly
rather than routing through `usecase.Apply` the way `pkg/stave/`
does. Both paths reach the same evaluation code, but they use
different application-layer entry points. This is a legacy of
the order the library was added; it is not a problem today
because behavior is compiler-shared, but it is an inconsistency
worth closing when the cost is low.

**Policy**: when `cmd/apply/` (or any CLI command with a
library-suitable equivalent) next requires a feature change that
affects its application-layer wiring, that iteration also
routes the command through `pkg/stave/` or `usecase.Apply`. The
feature change carries the refactor; iterations do not open
separate refactor PRs for unchanged commands.

Subsequent library-suitable commands — `Gate`, `Fix`, `Verify`,
`Trace` — similarly route through `pkg/stave/` when they next
require changes. Unchanged commands stay on their current path
until touched.

**Exception**: commands that are CLI-only by design never migrate
to the library path. That list includes `completion`, `doctor`,
`capabilities`, and the interactive `forge` wizards. They are
listed explicitly in the survey at
`docs/design/library-api-survey.md` under "Unsuitable for library
exposure."

## What this iteration did

Investigation only — no code moved. The boundary described above
was already in place. This document makes the shape explicit so
future contributors have a reference for:

- Which packages are shared core (the tables above).
- Why drift between CLI and library is currently prevented
  (both paths import `internal/app/eval`).
- When and how to migrate a CLI command to the library
  (refactor-on-touch).

A previous iteration (feat(stave): expose apply as a Go library
at pkg/stave, commit `c4800af42`) established the library. This
iteration did not modify that work; it documented the resulting
boundary.
