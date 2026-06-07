# pkg/stave: the facade pattern

## The rule

```
cmd/             →  imports ONLY pkg/stave  (the public API)
cmd/stave-mcp/   →  imports ONLY pkg/stave  (enforced today by a test)
pkg/stave/       →  the stable facade; orchestrates internal/ packages
internal/app/    →  application logic called BY pkg/stave
internal/core/   →  domain logic called BY internal/app
internal/adapters/ → infrastructure called BY internal/app
```

The point is one place where new capability lands: a `pkg/stave`
function. The CLI and the MCP server both consume it. New code paths
don't bypass the facade and re-implement orchestration from internal
parts.

## Current state — honest (updated 2026-06-07)

Six cmd packages are at the bar (zero `internal/` imports), each
enforced by a per-package `TestArchitecture_NoInternalImports`:
`stave-mcp`, `gaps`, `readiness`, `score`, `test`, `exportinvariants`.

The wider CLI is not there yet. **228 non-test files under `cmd/`
import 135 distinct `internal/` packages.** (The 2026-05 baseline was
214 / 161; the file count rose as the renderer-pattern factories
landed — they legitimately import the CLI-shaped helpers below.) The
top importers split into two categories:

| Imports from cmd/ | Package | Nature |
|---:|---|---|
| 113 | `internal/cli/ui` | error rendering, hints — CLI-shaped (**exempt**) |
| 81 | `internal/app/contracts` | engine ports — domain leakage |
| 67 | `internal/platform/fsutil` | path/file helpers — CLI-shaped (**exempt**) |
| 54 | `internal/core/kernel` | foundational types — domain leakage |
| 47 | `internal/core/controldef` | control type — domain leakage |
| 44 | `internal/platform/metadata` | offline-suffix help text — CLI-shaped (**exempt**) |

Two distinct categories:

- **CLI-infrastructure exemption** — `cli/ui`, `platform/fsutil`,
  `platform/metadata`, `util/jsonutil`. These are CLI-shaped *shared*
  helpers, not library API surface. They were originally slated to move
  under `cmd/cmdutil/` (Phase 2), but that is **architecturally
  impossible**: `internal/` itself consumes them (`fsutil` 21 internal
  importers, `jsonutil` 7, `metadata` 3, `cli/ui` 2 — and `cli/ui`
  imports `metadata`), and `internal/ → cmd/` is banned by
  `internal/core/enginetest/boundary_test.go` and
  `internal/app/architecture_dependency_test.go`. `internal/` is the
  correct home for shared code, so these four are an **explicit facade
  exemption**: a cmd/ file importing only `pkg/stave`, `cmd/cmdutil`,
  stdlib, and these four helpers is facade-clean. (The six "at the bar"
  packages are stricter — zero internal imports, not even the helpers,
  e.g. `cmd/score` surfaces exit-2 via `stave.ErrInvalidInput` instead
  of `ui.UserError`.)
- **Domain / orchestration leakage** (`core/*`, `app/*`,
  `adapters/*`) — these *are* the migration targets. Excluding the four
  exempt helpers, **201 cmd/ files still import 131 distinct internal
  packages** — that is the real Phase-3 surface. Every cmd/ file that
  loads snapshots, parses controls, or holds a core type directly is
  bypassing the facade.

## Why no "big bang" cutover

Re-exporting all 161 internal packages through `pkg/stave` would bloat
the public API and invert which side owns the orchestration. The
honest path is phased:

### Phase 1 — establish the rule (this commit)

- Enforce pkg/stave-only for `cmd/stave-mcp/` with a test
  (`TestArchitecture_NoInternalImports`). Done.
- Document the facade pattern (this file).
- Refresh `pkg/stave/doc.go` to enumerate the public functions so
  the surface is grep-able and reviewable.

### Phase 2 — designate the CLI-infrastructure exemption (revised 2026-06-07)

The original plan — move `cli/ui`, `platform/fsutil`,
`platform/metadata`, `util/jsonutil` into `cmd/cmdutil/` — turned out
to be **architecturally impossible**: those helpers are shared *with*
`internal/`, and `internal/ → cmd/` is forbidden (see Current state).
You cannot relocate a package that the lower layer depends on into a
higher layer without inverting the dependency.

Revised resolution: the four stay in `internal/` and become an explicit
**facade exemption** — cmd/ may import them without it counting as
leakage. This is documentation + accounting, not a code move. Impact is
small by itself: only ~27 cmd/ files had the four helpers as their
*sole* internal imports; the other 201 still leak domain/orchestration
packages. The exemption list (`internal/cli/ui`, `internal/platform/fsutil`,
`internal/platform/metadata`, `internal/util/jsonutil`) is what the
Phase-4 consolidated test will allow. The real work is Phase 3.

### Phase 3 — migrate one command at a time (started 2026-06-07)

- Pick a command (start with a small, recently-touched one — e.g.
  `cmd/contract`, `cmd/coverage`, or one of the `cmd/export/*`
  sub-commands). Replace each `internal/` import with either:
  - a `pkg/stave` function (if one exists for the user intent), or
  - a new `pkg/stave` function that wraps the internal call (named
    for user intent, simple input/output types).
- After each command is clean, add an `architecture_test.go` that
  enforces it. Two bar shapes:
  - **Zero-internal** (`TestArchitecture_NoInternalImports`) — the
    strictest; the original 6 packages use it (no helpers either).
  - **Facade-only / exemption** (`TestArchitecture_FacadeOnly`) — allows
    the four exempt CLI helpers; the realistic bar for most commands.

**First migration (2026-06-07): `cmd/inspect/compliance`.** Its only
domain dependency, `internal/compliance` (`ParseFramework` +
`ResolveControlCrosswalk`), moved into `stave.ResolveCrosswalk`
(`pkg/stave/crosswalk.go`). The command now imports only `pkg/stave`
plus the exempt `platform/fsutil` (file read) and `platform/metadata`
(offline help suffix), enforced by `TestArchitecture_FacadeOnly`. This
is the template: find the command's domain calls → wrap them in one
intent-named `pkg/stave` function → swap the import → add the
architecture test. ~200 leaky files remain.

### Phase 4 — enforce by default (started 2026-06-07, as a ratchet)

The end state is one cmd/-wide test that denies every `internal/` import
(bar the four exempt helpers) and the deletion of the per-command tests
and transitional comments. That flip can only happen once Phase 3 is
done — flipping today would fail on the ~64 still-leaky packages.

**Started as a ratchet** (`cmd/facade_ratchet_test.go`): one consolidated
test walks every leaf command package and holds a `facadeCleanBaseline`
of the packages that are already facade-clean (11 today; the `cmd/cmdutil`
subtree is excluded as the wrapper layer). It enforces a one-way ratchet —

- no baseline package may regress (gain a non-exempt internal import), and
- any package that *becomes* clean must be added to the baseline

— so the clean set only ever grows and Phase 3 progress is locked in
repo-wide. When the baseline covers every command package the leaky set
is empty; at that point flip the ratchet to a plain deny-all and delete
the per-command `architecture_test.go` files and the transitional
comments. The per-command tests stay until then (they hold the stricter
zero-internal bar for the six original packages).

## Naming guidance for new pkg/stave functions

When extracting orchestration into the facade, name for user intent:

| User intent | Existing function |
|---|---|
| Run evaluation | `Apply` |
| Validate inputs | `Validate` |
| Resolve compliance crosswalk | `ResolveCrosswalk` |
| Search the catalog | `SearchCatalog` |
| Explain one control | `ExplainControl` |
| Field-gap analysis | `Gaps` |
| Evaluability report | `Readiness` |
| Framework compliance (single) | `Compliance` |
| Framework compliance (multi) | `ComplianceMulti` |
| Diff two snapshots | `DiffSnapshots` |
| Build version + counts | `GetCapabilities` |

Each takes a simple options struct (not raw internal types) and
returns a result struct + error. If a candidate function doesn't map
to a user intent, it belongs in `internal/`, not in `pkg/stave`.

## Why this matters

Without the facade pattern:

- Every new command re-implements orchestration from raw internal
  parts. Changes to `internal/` break N command files instead of one
  facade function.
- The MCP server and the CLI evolve along separate paths even when
  they want the same capability. Bugs get fixed twice.
- New consumers (a Python SDK, another agent integration, the
  Workflow Guides' example scripts) have no clean library surface to
  call — they have to either shell out to the CLI or import internal/
  (which they can't, by Go's rules).

With the facade:

- Library is the source of truth; the CLI is a thin wrapper. Same
  capability, two transports. (Stated in `pkg/stave/doc.go`.)
- Engine refactors stay inside the facade.
- Anyone outside the module gets a real, stable Go API.
