# CLI Wiring Audit

**Date:** 2026-05-13

**Scope:** how each Cobra subcommand under `cmd/` receives its dependencies, where shared wiring lives, and which dependencies are implicit (pulled from a factory inside the command) vs explicit (passed at the call site).

**Top-level command directories:** 50 under `cmd/`
**Nested subcommand directories:** 37 (e.g. `cmd/diagnose/{artifacts,report,trace}`, `cmd/enforce/{baseline,cidiff,fix,gate}`, `cmd/initcmd/{alias,config,contextcmd,env}`)
**Registration sites:** 72 `AddCommand(...)` calls in `cmd/commands.go` plus per-group sub-registrations

## TL;DR — what's actually shared

The spec assumed a "shared bootstrap" anti-pattern from which commands implicitly pull dependencies. The codebase has two layers and neither is that:

1. **`cmd/bootstrap.go`** runs as `PersistentPreRunE` on every command. It executes a five-phase pipeline — `context → config → validate → logging → enrich` — that wires the cancelable context, project-config resolver, offline-guarantee check, logger / sanitizer, and Cobra-context enrichment. **It does not provide application dependencies** (no repos, no evaluators, no chain loaders). It's environmental setup.

2. **`cmd/cmdutil/compose/`** is where typed factory functions live. `compose.Factories` is a struct of nine factory function fields (`NewObsRepo`, `NewCtlRepo`, `NewCELEvaluator`, `NewChainLoader`, `NewSLALoader`, `NewSnapshotRepo`, `NewFindingWriter`, `NewS3Resolver`, plus a few specialised ones). `DefaultFactories()` populates them with production adapters. Tests substitute by passing alternative `Factories` values.

The real wiring question is: **does a command receive its factory functions at the call site (explicit) or call `compose.DefaultFactories()` itself (implicit)?**

## Bootstrap pipeline (cmd/bootstrap.go)

| Phase | What it does |
|---|---|
| `phaseContext` | Cancelable root context; validates predicate/exposure builtins |
| `phaseConfig` | Builds `appconfig.GovernanceResolver` from project + user config |
| `phaseValidate` | Offline-guarantee check; dev/prod guard; config health |
| `phaseLogging` | UI no-color toggle; sanitizer setup; structured logger; replays config warnings |
| `phaseEnrich` | Stashes logger in `cmd.Context()` for command retrieval |

These are all environmental concerns. Migrating them out is out of scope — they're correctly factored.

## The factory composition (cmd/cmdutil/compose/)

Files and their roles:

| File | Purpose |
|---|---|
| `infra.go` | `Factories` struct + `DefaultFactories()` production wiring; typed factory function aliases (`ObsRepoFactory`, `CtlRepoFactory`, etc.) |
| `controls.go` | Control-loading composition |
| `observations.go` | Observation-loading composition |
| `chains.go` | Chain-definition loader composition |
| `sla.go` | SLA-provider composition |
| `output.go` | Finding-writer composition (per `--format`) |
| `artifacts.go` | Prior-assessment loader composition |
| `git.go` | Git-history loader composition |
| `evalctx.go` | Evaluation context assembly |
| `resolve.go` | Path / asset-set resolver |

`Factories` holds these typed factory functions:

```
NewObsRepo                 func() (ObservationRepository, error)
NewStdinObsRepo            func(io.Reader) (ObservationRepository, error)
NewCtlRepo                 func() (ControlRepository, error)
NewFindingWriter           func(OutputFormat, bool) (FindingMarshaler, error)
NewCELEvaluator            func() (PredicateEval, error)
NewSnapshotRepo            func() (SnapshotReader, error)
NewChainLoader             func() (ChainDefinitionLoader, error)
NewSLALoader               func() (SLAProvider, error)
NewArtifactLoader          func() (ArtifactLoader, error)
NewSnapshotBundleLoader    func() (SnapshotBundleLoader, error)
NewBuiltinControlStore     func() ([]ControlDefinition, error)
NewS3Resolver              func() risk.PermissionResolver
```

## The three wiring patterns

After auditing each `NewCmd(...)` constructor and each `runXxx` function:

### Pattern A — explicit factory args at the call site (good, low-cost)

`commands.go` wires `f := compose.DefaultFactories()` once, then passes specific factory functions to `NewCmd(...)`. The command receives only the factories it needs.

**Commands (≈14):**

| Command | Factories received |
|---|---|
| `apply validate` (`applyvalidate.NewCmd`) | obs, ctl, CEL, ui-runtime |
| `apply verify` (`applyverify.NewCmd`) | obs, ctl, CEL, ui-runtime |
| `diagnose trace` (`diagnose.NewTraceCmd`) | ctl, snapshot |
| `diagnose explain` (`diagnose.NewExplainCmd`) | ctl |
| `expand` (`expand.NewCmd`) | ctl |
| `export` (`staveexport.NewCmd`) | ctl, CEL |
| `exportsir` (`staveexportsir.NewCmd`) | ctl, obs, CEL |
| `inspect` (`inspect.NewInspectCmd`) | S3 resolver |
| `lint`, `fmt`, `controls`, `packs` under `diagnose artifacts` | mostly ctl |
| `coverage` | ctl |
| `test` (`stavetest.NewCmd`) | ctl |
| `snapshotdiff` | ctl |
| `enforce graph` | ctl + snapshot loader |

**Verdict:** good. Test code can substitute `Factories`. Migration not needed.

### Pattern B — explicit Deps struct (good, but inconsistent file layout)

The command exports a `Deps` struct with explicit factory function fields; `commands.go` constructs the struct inline at the call site.

**Commands (≈10):**

| Command | Deps location | File layout |
|---|---|---|
| `apply` | `cmd/apply/deps.go` | **dedicated file (canonical)** |
| `doctor` | `cmd/doctor/cmd.go` | inline |
| `diagnose report` | `cmd/diagnose/report/cmd.go` | inline |
| `enforce baseline` | `cmd/enforce/baseline/cmd.go` | inline |
| `enforce cidiff` | `cmd/enforce/cidiff/cmd.go` | inline |
| `enforce fix` | `cmd/enforce/fix/cmd.go` (`Deps` + `LoopDeps`) | inline |
| `enforce gate` | `cmd/enforce/gate/cmd.go` | inline |
| `exempt` | `cmd/exempt/cmd.go` | inline (but **also** calls compose internally; see Pattern C) |
| `rank` | `cmd/rank/cmd.go` | inline (but **also** calls compose internally) |
| `report` | `cmd/report/cmd.go` | inline (but **also** calls compose internally) |

**Verdict:** the struct pattern is correct; only `apply` has it split into a dedicated `deps.go` file. The migration cost to bring the other nine in line with `apply`'s file convention is mechanical (one Edit per command).

### Pattern C — implicit: command calls `compose.DefaultFactories()` itself

The command takes **no factory arguments at `NewCmd()`**, then reaches into `compose.DefaultFactories()` from inside `runXxx`. This is the actual implicit-wiring set — tests can't substitute the factory because the production wiring is hard-coded inside the command.

**Commands (8):**

| Command | Internal compose call | Receives via `NewCmd(...)` |
|---|---|---|
| `bisect` | `cmd/bisect/run.go:43` — `f := compose.DefaultFactories()` | nothing |
| `exempt` | `cmd/exempt/cmd.go:34` | nothing externally, but exports `Deps` struct used internally |
| `export` (`staveexport`) | internal | nothing |
| `forensics` | internal | nothing |
| `map` | internal | nothing |
| `rank` | `cmd/rank/cmd.go:61` — `f := compose.DefaultFactories()` | nothing |
| `report` | internal | nothing |
| `test` | internal | nothing |

These are the migration targets. Each should be reshaped so `commands.go` passes the specific factory functions it needs — same pattern as Pattern A or B.

### Pattern D — truly self-contained (no factory dependency)

The command takes no factory arguments AND doesn't call compose internally. These are analysis-only commands that work on `out.v0.1` assessment files (already-produced output) rather than raw observations.

**Commands (25):**

`attest`, `budget`, `bundle`, `cel`, `collect`, `compare`, `consolidate`, `enrich`, `exportinvariants`, `forge`, `inventory`, `metrics`, `monitor`, `nep`, `path`, `plan`, `profile`, `sanitize`, `score`, `scorecard`, `simulate`, `sla`, `telemetry`, `trend`, `verify`, `watch`

**Verdict:** correctly factored. No migration needed.

## Dependency matrix (the spec's table, filled in)

The spec's table conflated bootstrap with dependency injection. Reframed below to track only the factory-style dependencies:

| Command | Obs | Ctl | CEL | Chain | SLA | Snapshot | Out | Other | Wiring via |
|---|---|---|---|---|---|---|---|---|---|
| `apply` | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | artifact, bundle | **B** explicit `Deps` (deps.go) |
| `exportsir` | ✅ | ✅ | ✅ | — | — | — | — | — | **A** factory args |
| `exportinvariants` | — | — | — | — | — | — | — | — | **D** self-contained |
| `export` (compliance/oscal) | — | ✅ | ✅ | — | — | — | — | — | **A** factory args |
| `apply validate` | ✅ | ✅ | ✅ | — | — | — | — | ui-runtime | **A** factory args |
| `apply verify` | ✅ | ✅ | ✅ | — | — | — | — | ui-runtime | **A** factory args |
| `diagnose trace` | — | ✅ | — | — | — | ✅ | — | — | **A** factory args |
| `diagnose explain` | — | ✅ | — | — | — | — | — | — | **A** factory args |
| `diagnose report` | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | git, artifact | **B** inline Deps |
| `trend` | — | — | — | — | — | — | — | reads out.v0.1 only | **D** self-contained |
| `bisect` | ✅ | ✅ | ✅ | — | — | — | — | — | **C** internal compose |
| `watch` | ✅ | ✅ | ✅ | ✅ | — | — | ✅ | — | **D** self-contained (constructs internally with concrete adapters) |
| `rank` | — | — | — | — | — | — | — | bundle loader | **C** (also exports `Deps` for tests) |
| `exempt` | — | ✅ (builtin) | — | — | — | — | — | — | **C** (also exports `Deps`) |
| `report` | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | artifact | **C** (also exports `Deps`) |
| `forensics` | ✅ | — | — | — | — | ✅ | — | — | **C** internal compose |
| `map` | — | ✅ | — | — | — | — | — | mitre matrix | **C** internal compose |
| `test` | — | ✅ | ✅ | — | — | — | — | fixture loader | **A** factory args + **C** internal |
| `controls` (list/show) | — | ✅ | — | — | — | — | — | — | **A** factory args |
| `inspect` | — | — | — | — | — | — | — | S3 resolver | **A** factory args |
| `consolidate`, `collect`, `bundle`, `attest`, `simulate`, `compare`, `score`, `scorecard`, `plan`, `verify`, `metrics`, `monitor`, `nep`, `cel`, `forge`, `sanitize`, `enrich`, `inventory`, `profile`, `path`, `budget`, `telemetry`, `sla`, `expand` | varies | varies | varies | varies | varies | varies | varies | varies | **D** self-contained or **A** explicit |

## Blast-radius ranking

Counted by how many distinct factory function fields a command consumes (= migration surface if reshaped):

1. **`apply`** — 7+ factories (obs, ctl, CEL, chain, SLA, finding writer, artifact, bundle). Highest blast radius. Already migrated to **Pattern B** with a dedicated `deps.go`. **Migrate last** if at all.
2. **`report`** — 6 factories. **Pattern C** today; needs migration.
3. **`diagnose report`** — 6 factories. **Pattern B** inline; promote to `deps.go`.
4. **`bisect`** — 3 factories. **Pattern C**; migrate.
5. **`forensics`** — 2 factories. **Pattern C**; migrate.
6. **`rank`** — 1 factory (`NewSnapshotBundleLoader`). **Pattern C**; migrate.
7. **`exempt`** — 1 factory (`NewBuiltinControlStore`). **Pattern C**; migrate.
8. **`test`** — 1 factory (`NewCtlRepo`) at construction, more internally. Mixed **A/C**; tighten to pure A.
9. **`export`** (staveexport) — 1 factory. **Pattern C**; migrate.
10. **`map`** — 1 factory. **Pattern C**; migrate.

## Recommended migration order

Start with the smallest blast radius (one factory each, mechanical translation) before tackling the bigger ones:

1. `rank` — 1 factory, already has inline `Deps`; promote to `cmd/rank/deps.go` and accept factory at `NewCmd(deps)`
2. `exempt` — 1 factory; same shape
3. `map` — 1 factory; pull `compose.DefaultFactories()` call out into `commands.go`
4. `export` (staveexport, the OSCAL one) — 1 factory; same shape
5. `test` — tighten the mixed pattern
6. `forensics` — 2 factories
7. `bisect` — 3 factories
8. `report` — 6 factories; promote inline `Deps` to dedicated `deps.go`
9. `diagnose report` — 6 factories; promote inline `Deps` to dedicated `deps.go`
10. `apply` — already migrated; only the `deps.go` convention to extend across siblings

For the Pattern-B-but-inline commands (`doctor`, `enforce baseline / cidiff / fix / gate`), promoting inline `Deps` structs to dedicated `deps.go` files is pure file-organization — a single Edit per command with no logic change.

## What this audit does NOT recommend

- **Don't change `bootstrap.go`.** The five phases are environmental setup; they don't carry application dependencies and they're cleanly factored.
- **Don't refactor `compose.Factories`.** The typed-factory-struct pattern is good. The migration is about pushing the `DefaultFactories()` call out to the topmost boundary (`commands.go`), not changing the factory shape itself.
- **Don't touch the 25 self-contained commands.** They don't need to interact with `compose` at all.
- **Don't migrate `apply` again.** It's the canonical example; the rest should converge on its pattern.

## Counts summary

| Bucket | Count |
|---|---|
| Top-level command dirs (excl. cmdutil + stave / stave-dev / stave-mcp binaries) | 46 |
| Pattern A (explicit factory args) | ≈14 |
| Pattern B (explicit `Deps` struct) — only `apply` in a dedicated `deps.go` | ≈10 |
| Pattern C (implicit `compose.DefaultFactories()` inside the command) | 8 |
| Pattern D (truly self-contained) | 25 |
| **Total to migrate (Pattern C)** | **8** |
| **Total to relocate inline `Deps` to `deps.go` files** | **9** (every Pattern-B command except apply) |

Iteration 2 (refactor) addresses the eight Pattern-C commands first, then optionally promotes the nine inline `Deps` to dedicated files for file-layout consistency with `apply`.
