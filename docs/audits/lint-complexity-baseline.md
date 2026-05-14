# Complexity Baseline

**Date:** 2026-05-13
**Iteration:** ceilings enabled, ratchet established

## Thresholds (current)

| Metric | Linter | Threshold | Current production max |
|---|---|---|---|
| Function length (lines) | `funlen.lines` | **210** | 208 (`builtinAliases`) |
| Function length (statements) | `funlen.statements` | **90** | 85 (`renderTrendTable`) |
| Cyclomatic complexity | `gocyclo.min-complexity` | **32** | 31 (`mergeEdgeProperties`) |
| Cognitive complexity | `gocognit.min-complexity` | **85** | 84 (`stringifiedPolicyFacts`) |
| Nesting depth | `nestif.min-complexity` | **12** (unchanged) | <12 (already clean) |

Each ceiling sits 1–5 above the current production max. **No existing
function fails today.** New code that exceeds the ceiling fails the
build.

`cyclop` is intentionally **not** enabled — it overlaps `gocyclo` with a
different scale, and the playbook says pick one. `gocyclo` is the more
established option.

## Why these numbers, not aggressive defaults

A naïve `funlen.lines: 60` (the linter's own default) would flag 50
production functions on day one. Most of those are sequential CLI
command handlers — long but linear, with no nesting. Splitting them
across helper functions would *reduce* readability because the reader
would have to chase symbols across files to follow a 7-step pipeline.

The ratchet approach calibrates ceilings to the codebase's actual
shape, then tightens iteratively as the top offenders refactor during
normal development work — not in a forced cleanup pass.

## Top 5 by each metric (snapshot at baseline)

### Cyclomatic complexity (gocyclo)

| Score | Function | File |
|---:|---|---|
| 31 | `mergeEdgeProperties` | `internal/adapters/graph/builder.go:540` |
| 26 | `runCompliance` | `cmd/export/compliance/run.go:27` |
| 26 | `literal` | `internal/adapters/cel/env.go:401` |
| 26 | `ruleToExpr` | `internal/adapters/cel/compiler.go:234` |
| 25 | `assumeEdgeFacts` | `cmd/exportsir/facts.go:1544` |

`internal/tools/ccmbackfill/` has higher scores (42, 36, 32, etc.) but
the whole `internal/tools/` tree is path-excluded from lint.

### Cognitive complexity (gocognit)

| Score | Function | File |
|---:|---|---|
| 84 | `stringifiedPolicyFacts` | `cmd/exportsir/facts.go:929` |
| 71 | `mergeEdgeProperties` | `internal/adapters/graph/builder.go:540` |
| 58 | `DetectChains` | `internal/core/evaluation/risk/chain_engine.go:77` |
| 57 | `conditionFacts` | `cmd/exportsir/facts.go:787` |
| 50 | `assumeEdgeFacts` | `cmd/exportsir/facts.go:1544` |

`cmd/exportsir/facts.go` shows up three times — it's the SIR fact
projector, a long switch over fact families. A natural extraction
target if this file ever needs deeper edits.

### Function length (funlen.lines, prod only)

| Lines | Function | File |
|---:|---|---|
| 208 | `builtinAliases` | `internal/adapters/predicate/aliases.go:13` |
| 176 | `WireCommands` | `cmd/commands.go:103` |
| 154 | `runCollect` | `cmd/collect/cmd.go:145` |
| ~140 | (several) | various |
| 120 | (cutoff for the next 16 functions) | various |

`builtinAliases` is a static alias-name table (declaration with no
branching) — long but not complex. `WireCommands` is the
cobra `AddCommand` wiring root — long but linear. Both are obvious
candidates for `//nolint:funlen` justification if the ceiling ever
needs to tighten below 210.

### Function length (funlen.statements, prod only)

| Statements | Function | File |
|---:|---|---|
| 85 | `renderTrendTable` | `cmd/trend/render_table.go:30` |
| 81 | `renderTrendOpenMetrics` | `cmd/trend/render_openmetrics.go:8` |
| 81 | `runWizard` | `cmd/forge/new.go:114` |
| 80 | `WireCommands` | `cmd/commands.go:103` |
| 71 | `runCollect` | `cmd/collect/cmd.go:145` |

## Ratchet schedule

The intent is to tighten as the top offenders refactor during normal
development, **not** to force a refactoring pass. No PR should land
explicitly to "lower the ceiling" — instead, when someone touches one
of the top offenders for unrelated reasons and breaks it into smaller
pieces, the linter ceiling can drop to match the new max.

A reasonable target a year out:

| Metric | Today | One-year target |
|---|---:|---:|
| `funlen.lines` | 210 | 150 |
| `funlen.statements` | 90 | 60 |
| `gocyclo` | 32 | 20 |
| `gocognit` | 85 | 40 |

If those targets feel painful, the codebase has more refactoring debt
than the iteration cadence allows; if they feel trivial, tighten faster.

## Top offenders worth refactoring (priority order)

Picked by "highest leverage if it ever gets touched anyway":

1. **`mergeEdgeProperties`** (`internal/adapters/graph/builder.go:540`)
   — cyclo 31, cognit 71. Sits in the graph-property-merge code which
   is touched on most new asset/edge types. Most-likely to be edited.
2. **`stringifiedPolicyFacts`** + **`conditionFacts`** + **`assumeEdgeFacts`**
   (`cmd/exportsir/facts.go`) — cognit 84/57/50. The SIR fact
   projector. A future SIR fact addition is the natural extraction
   point.
3. **`DetectChains`** (`internal/core/evaluation/risk/chain_engine.go:77`)
   — cognit 58. Compound-chain detection; new chain capability
   tokens land here.
4. **`renderTrendTable`** + **`renderTrendOpenMetrics`** (`cmd/trend/`)
   — statements 85/81. Output formatters for the trend command.
5. **`WireCommands`** (`cmd/commands.go:103`) — lines 176, statements
   80. The cobra wiring root. Long but linear; not a top refactoring
   target. Marked here only so it doesn't surprise anyone scanning the
   list.

## Verification commands

```bash
# Lint passes today with the configured ceilings
cd stave && make lint

# Re-measure the production maxes (skip internal/tools and tests)
gocyclo -top 20 ./internal/ ./cmd/ ./pkg/ \
    | grep -vE 'internal/tools/|_test\.go|TestSuiteRoots' | head -10
gocognit -top 20 ./internal/ ./cmd/ ./pkg/ \
    | grep -vE 'internal/tools/|_test\.go' | head -10

# Tighten one ceiling by 1 to confirm the gate fires
# (edit .golangci.yml, run make lint, revert)
```
