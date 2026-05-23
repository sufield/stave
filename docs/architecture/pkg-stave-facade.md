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

## Current state — honest

`cmd/stave-mcp/` is at the bar: zero `internal/` imports.
`TestArchitecture_NoInternalImports` enforces this and runs on every
build.

The wider CLI is not there yet. **214 Go files under `cmd/` import
161 distinct `internal/` packages.** The top offenders are CLI
infrastructure, not orchestration:

| Imports from cmd/ | Package | Nature |
|---:|---|---|
| 84 | `internal/cli/ui` | error rendering, hints — genuinely CLI-shaped |
| 63 | `internal/platform/fsutil` | path/file helpers — CLI-shaped |
| 44 | `internal/platform/metadata` | offline-suffix help text — CLI-shaped |
| 36 | `internal/core/kernel` | foundational types — domain leakage |
| 35 | `internal/app/contracts` | engine ports — domain leakage |
| 30 | `internal/core/controldef` | control type | domain leakage |
| 27 | `internal/core/asset` | asset type | domain leakage |
| 19 | `internal/app/config` | config loading | orchestration leakage |
| 18 | `internal/adapters/observations` | snapshot loader | orchestration leakage |
| 15 | `internal/core/evaluation/remediation` | remediation prose | domain leakage |

Two distinct categories show up in those rows:

- **CLI infrastructure** (`cli/ui`, `platform/fsutil`,
  `platform/metadata`, `util/jsonutil`) — these are legitimately
  CLI-shaped helpers, not library API surface. They could be moved
  under `cmd/cmdutil/` rather than re-exported through `pkg/stave`.
- **Domain / orchestration leakage** (`core/*`, `app/*`,
  `adapters/observations`) — these *are* the migration targets.
  Every cmd/ file that loads snapshots, parses controls, or holds a
  core type directly is bypassing the facade.

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

### Phase 2 — split the import set

- Move pure CLI helpers (`cli/ui`, `platform/fsutil`,
  `platform/metadata`, `util/jsonutil`) into `cmd/cmdutil/` — they
  are CLI-shaped and don't belong in `internal/` if cmd/ is the
  only consumer. After the move they're no longer "internal
  imports" from cmd/'s perspective; only the genuine orchestration
  imports remain.

### Phase 3 — migrate one command at a time

- Pick a command (start with a small, recently-touched one — e.g.
  `cmd/contract`, `cmd/coverage`, or one of the `cmd/export/*`
  sub-commands). Replace each `internal/` import with either:
  - a `pkg/stave` function (if one exists for the user intent), or
  - a new `pkg/stave` function that wraps the internal call (named
    for user intent, simple input/output types).
- After each command is clean, add it to the architecture test's
  enforced set.

### Phase 4 — enforce by default

- When the enforced set covers every command directory under
  `cmd/`, flip the test to scan all of `cmd/` and remove the
  per-command opt-in list.
- Delete all "Phase cutover" / "transitional" comments —
  the debt is resolved.

## Naming guidance for new pkg/stave functions

When extracting orchestration into the facade, name for user intent:

| User intent | Existing function |
|---|---|
| Run evaluation | `Apply` |
| Validate inputs | (Phase 3 target — currently `cmd/validate` calls internal) |
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
