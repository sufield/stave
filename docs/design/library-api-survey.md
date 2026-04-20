# Library API Survey

**Date**: 2026-04-20
**Purpose**: Inventory what's currently wired as CLI commands, trace the
implementation path for each, and classify library-exposure suitability.
Output feeds the subsequent library-design iteration; this document
reports what exists — it does not propose the library design.

---

## 1. Command inventory

Stave's Cobra tree is wired in `cmd/commands.go:103 WireCommands(app *App)`.
The inventory below counts top-level commands by category; subcommand
trees are nested under their parents.

### Getting-started (1)

| Command | Source | Short description |
|---|---|---|
| `stave init` | `cmd/init/` (`initcmd.NewGenerateCmd`) + `initconfig`/`initalias` variants | Generate starter project layout, config, command aliases |

### Control engine (5 + 3 diagnose subs)

| Command | Source | Short description |
|---|---|---|
| `stave apply validate` | `cmd/apply/validate/` | Pre-flight readiness check on controls + observations |
| `stave apply` | `cmd/apply/` | Run control evaluation; emit findings as JSON/text/SARIF |
| `stave apply verify` | `cmd/apply/verify/` | Verify apply-output byte-determinism |
| `stave diagnose` (parent) | `cmd/diagnose/commands.go` | Explain why a control fired / didn't fire |
| &nbsp;&nbsp;`diagnose trace` | `cmd/diagnose/trace_run.go` | Emit per-clause evaluation trace |
| &nbsp;&nbsp;`diagnose prompt` | `cmd/diagnose/prompt.go` | Render remediation prompt for AI consumers |
| &nbsp;&nbsp;`diagnose explain-narrative` | `cmd/diagnose/explain_narrative.go` | Plain-language narrative for a finding |
| `stave explain` | `cmd/diagnose/explain.go` | Standalone explain (top-level) |

### Workflow / CI (10)

| Command | Source | Short description |
|---|---|---|
| `stave enforce status` | `cmd/enforce/status/` | Report gating status without re-evaluating |
| `stave ci baseline` | `cmd/enforce/baseline/` | Save/check baseline evaluation |
| `stave ci gate` | `cmd/enforce/gate/` | Fail CI if thresholds exceeded |
| `stave ci fix` | `cmd/enforce/fix/` | Apply fix plan to a single finding |
| `stave ci fix-loop` | `cmd/enforce/fix/` (loop deps) | Iterative fix + re-evaluate cycle |
| `stave ci diff` (CI diff) | `cmd/enforce/cidiff/` | Diff two evaluations against a baseline |
| `stave snapshot diff` | `cmd/enforce/diff/` | Diff two observation snapshots |
| `stave snapshot query` | `cmd/commands.go:396 newSnapshotQueryCmd` | Query snapshot archive metadata |
| `stave snapshot ...` (prune subtree) | `cmd/prune/` | Cleanup, archive, upcoming, quality, plan, hygiene, manifest |
| `stave enforce graph` | `cmd/enforce/graph/` | Graph of control → finding dependencies |

### Export & interop (3)

| Command | Source | Short description |
|---|---|---|
| `stave export` | `cmd/export/` (via `staveexport`) | Export findings to external formats |
| `stave enforce generate` | `cmd/enforce/generate/` | Generate CI scaffolding for enforcement |
| `stave diagreport report` | `cmd/diagreport/` | Compose a diagnostic report |

### Data & artifacts (4)

| Command | Source | Short description |
|---|---|---|
| `stave lint` / `fmt` / `controls` / `packs` | `cmd/artifacts*/` | Lint, format, inspect control files + packs |

### Standalone top-levels (~40)

Each exposes a single narrow capability. Grouped by intent:

- **Introspection / reporting**: `inspect`, `coverage`, `metrics`,
  `trend`, `scorecard`, `budget`, `score`, `sla`, `report`, `plan`,
  `compare`, `simulate`, `verify`
- **Authoring / testing**: `forge`, `test`, `profile`, `cel`
- **Security chronology / forensics**: `bisect`, `forensics`, `watch`,
  `monitor`, `attest`, `bundle`, `collect`
- **Posture analytics**: `nep`, `path`, `map`, `rank`, `consolidate`,
  `exempt`, `snapshotdiff`, `enrich`, `inventory`
- **Infrastructure utilities**: `sanitize`, `telemetry`, `doctor`,
  `capabilities`, `completion`, `schemas`, `version`, `config`

Each lives in `cmd/<name>/` with a `NewCmd()` or `NewCmd(...)`
constructor that returns `*cobra.Command`. Full source-path listing
from `cmd/commands.go:116–293`.

### Command count summary

- Top-level AddCommand calls: **53** (at `cmd/commands.go`)
- Nested subcommand trees under `snapshot` (~9), `ci` (~6),
  `diagnose` (3), `forge` (~7), plus ~5 others — brings the reachable
  surface to roughly **85 distinct CLI invocations**.

---

## 2. Per-command invocation documentation

Exhaustive flag-by-flag documentation for 85 command invocations is
outside this survey's scope. Instead, this section documents the
**patterns** commands follow, with apply documented exhaustively in §6.

### Standard command shape

Every Stave command's `cmd.go` follows a consistent structure
(convention documented in `CLAUDE.md`):

1. **Options struct** carrying flag values (usually named `Options`
   or `options`; see `cmd/apply/cmd.go:66 type Options`).
2. **Constructor** `NewCmd(...) *cobra.Command` or `New{Name}Cmd(...)`
   taking factory dependencies as arguments.
3. **`PreRunE`**: resolve config defaults → normalize paths → validate
   flags. Uses the `opts.Prepare(cmd)` / `opts.normalize()` pattern.
4. **`RunE`**: construct request → call app/domain service → format output.
   Kept thin (no flag parsing).
5. **File layout**: `cmd.go` (command construction), `run.go`
   (execution logic), `options.go` (flag structs + resolution),
   `output.go` (rendering), `deps.go` (dependency wiring).

### Standardized flag names (project-wide contract)

From `CLAUDE.md` § "Flag Naming Conventions". New commands MUST use
the same names for the same concepts:

| Flag | Concept | Default |
|---|---|---|
| `--controls` / `-i` | Control definitions dir | `controls` |
| `--observations` / `-o` | Observation snapshots dir | `observations` |
| `--in` | Single input file or `-` for stdin | — |
| `--input` | Observation bundle file (`apply --profile` only) | — |
| `--format` / `-f` | Output format (`text`/`json`/`sarif`) | varies per command |
| `--max-unsafe` | Maximum allowed unsafe duration | from project config |
| `--now` | Override current time (RFC3339) for deterministic output | — |
| `--quiet` | Suppress output (exit code only) | false |
| `--sanitize` | Sanitize infrastructure identifiers from output | false |

### Global persistent flags (all commands)

`cmd/root.go:23 globalFlagsType` — every subcommand inherits these:

`--quiet`, `--yes`, `-v`/`--verbosity`, `--log-level`,
`--log-format`, `--log-file`, `--log-timestamps`, `--log-timings`,
`--sanitize`, `--path-mode`, `--force`, `--allow-symlink-out`,
`--require-offline`, `--strict`, `--no-color`, `--cpu-profile`,
`--mem-profile`.

### Exit codes (project-wide contract)

`internal/cli/ui/error.go:17`:

| Exit | Meaning |
|---|---|
| `0` | Success / no violations |
| `1` | `security-audit` gating (used only by that command) |
| `2` | `ExitInputError` — invalid input, flags, schema validation |
| `3` | `ExitViolations` — evaluation completed with findings |
| `4` | `ExitInternal` — unexpected internal error |
| `130` | SIGINT |

### Standard output contract

- **stdout**: primary output (JSON/text/SARIF body). Machine-readable
  formats are preserved in quiet mode.
- **stderr**: progress, diagnostic messages, hints, error renderings.
  Never mixed with stdout.
- **Files**: written only when an explicit flag requests a path (e.g.,
  `--log-file`, `--cpu-profile`, `--output`).

### Environment variables

Read via `cliflags.RegisterControlsFlag` / `cliflags.WithDynamicDefaultHelp`:

- `STAVE_CONTROLS_DIR`, `STAVE_OBSERVATIONS_DIR`, `STAVE_MAX_UNSAFE`
- `STAVE_TRACE` (enables per-apply logic trace to file)
- `NO_COLOR` (standard), `STAVE_DEBUG`, `STAVE_DEV_VALIDATE_FINDINGS`
- `STAVE_LOG_FORMAT`, `STAVE_LOG_FILE`, etc.

### Standard side-effect posture

Most commands are **pure reads** except:

- `stave init` — writes project scaffolding
- `stave enforce generate` — writes CI config files
- `stave ci baseline --save` — writes baseline JSON
- `stave snapshot prune/archive` — deletes/moves snapshot files
- `stave forge new/scaffold` — writes control YAML
- `stave config` — writes settings files

---

## 3. Per-command implementation tracing

The codebase separates CLI wiring from core logic through a
**hexagonal layering**:

```
cmd/{name}/                 ← Cobra plumbing (flags, PreRunE, RunE)
cmd/cmdutil/compose/        ← Dependency factories (ObsRepoFactory, CtlRepoFactory, ...)
internal/app/{use-case}/    ← Application-layer orchestration (78 packages)
internal/core/usecase/      ← Hexagonal "use case" façades (partial coverage — see below)
internal/core/{domain}/     ← Core domain types + engine
internal/adapters/{tech}/   ← Adapter implementations (YAML loaders, JSON/SARIF writers, etc.)
```

### Dependency injection pattern

Commands receive dependency factories at construction:

```go
// cmd/commands.go:120
root.AddCommand(apply.NewApplyCmd(apply.Deps{
    NewObsRepo:       f.NewObsRepo,         // compose.ObsRepoFactory
    NewCtlRepo:       f.NewCtlRepo,         // compose.CtlRepoFactory
    NewStdinObsRepo:  f.NewStdinObsRepo,
    NewFindingWriter: f.NewFindingWriter,   // compose.FindingWriterFactory
    NewCELEvaluator:  f.NewCELEvaluator,    // compose.CELEvaluatorFactory
}))
```

Factory types live in `cmd/cmdutil/compose/infra.go`:

- `ObsRepoFactory = func() (appcontracts.ObservationRepository, error)`
- `CtlRepoFactory = func() (appcontracts.ControlRepository, error)`
- `CELEvaluatorFactory = func() (policy.PredicateEval, error)`
- `FindingWriterFactory = func(fmt, validate) (appcontracts.FindingMarshaler, error)`
- `SnapshotRepoFactory`, `SnapshotLoader`, `AssetLoaderFunc`

### Core function per command (sampled)

| Command | Core function | Input | Output |
|---|---|---|---|
| `apply` | `(*AuditWorkflow).PerformAssessment` at `internal/app/eval/workflow.go:90` | `ctx, AssessmentConfig` | `ComplianceReport, SecurityState, error` |
| `apply validate` | `appvalidation.Run` | `ValidationRequest` | `ValidationResult` |
| `diagnose` | `appdiagnose.Diagnose` | `DiagnoseRequest` | `DiagnoseResponse` |
| `diagnose trace` | `apptrace.Run` | `TraceRequest` | `TraceResponse` |
| `enforce gate` | `usecase.Gate` at `internal/core/usecase/gate.go:N` | `ctx, GateRequest, GateDeps` | `GateResponse, error` |
| `enforce fix` | `usecase.Fix` at `internal/core/usecase/fix.go:N` | `ctx, FixRequest, FixDeps` | `FixResponse, error` |
| `enforce fix-loop` | `usecase.FixLoop` | `ctx, FixLoopRequest, LoopDeps` | `FixLoopResponse` |
| `snapshotdiff` | `appdiff.Run` | `DiffRequest` | `DiffResponse` |
| `monitor` | `appmon.Run` | `options + fsnotify.Watcher` | (long-running) |
| `forge new` | interactive wizard in `cmd/forge/new.go` | terminal prompts | control YAML written |

### Layering observation — `usecase` coverage is partial

`internal/core/usecase/` defines five use-case entry points:

- `usecase.Apply(ctx, ApplyRequest, ApplyDeps)` — `apply.go:48`
- `usecase.Fix(ctx, FixRequest, FixDeps)` — `fix.go`
- `usecase.FixLoop(ctx, FixLoopRequest, LoopDeps)` — `fix.go`
- `usecase.Gate(ctx, GateRequest, GateDeps)` — `gate.go`
- `usecase.Verify(ctx, Request, VerifyDeps)` — `verify.go`
- `usecase.Trace(ctx, TraceRequest, TraceDeps)` — `trace.go`

**But only `Fix` and `Gate` are actually wired through from the CLI
layer** (grep `usecase.` in `cmd/`). `cmd/apply/` goes directly
through `appeval.AuditWorkflow`, bypassing `usecase.Apply`.
`cmd/diagnose/` uses its own `appdiagnose` path. `cmd/apply/verify/`
doesn't call `usecase.Verify`. This asymmetry is load-bearing for the
library design: the usecase package is the natural library entry
shape but is currently under-utilized by the CLI.

---

## 4. Library-suitability classification

### Suitable for library exposure (direct entry — use case already exists)

| Command | Entry point | Shape |
|---|---|---|
| `apply` | `usecase.Apply(ctx, ApplyRequest, ApplyDeps) → (ApplyResponse, error)` | Pure I/O around a deterministic evaluation |
| `apply validate` | `appvalidation.Run(...)` | Pre-flight check; bool + errors |
| `enforce gate` | `usecase.Gate(...)` | Comparison → pass/fail enum |
| `enforce fix` | `usecase.Fix(...)` | Single-finding fix plan |
| `enforce fix-loop` | `usecase.FixLoop(...)` | Iterative fix + re-eval |
| `apply verify` | `usecase.Verify(...)` | Byte-determinism check |
| `diagnose trace` | `usecase.Trace(...)` | Per-clause trace record |
| `snapshotdiff` | `appdiff.Run(...)` | Structured diff result |
| `snapshot query` | Ad hoc inline function at `cmd/commands.go:396` | Inventory walk; cleanly extractable |
| `coverage` | `stavecoverage.Run(...)` | Catalog-coverage analysis |
| `score` | `appscore.Compute(...)` | Numeric posture score |
| `rank` | `staverank.Run(...)` | Priority-ordered finding list |
| `sla` | `appsla.Evaluate(...)` | SLA-status enum per finding |

### Suitable after restructuring (CLI plumbing entangled with core logic)

See §7 for the specific work.

### Unsuitable for library exposure

- **`monitor` / `watch`** — continuous long-running loop driven by
  `fsnotify`. A library-shape consumer would want an iterable of
  snapshots instead, which is a different primitive.
- **`forge new` / `forge scaffold`** — interactive TUI wizard writing
  control YAML via terminal prompts. No inputs/outputs translate to a
  programmatic call without a full rewrite.
- **`completion`** — emits shell completion scripts. Not a library
  concept.
- **`capabilities`** — dumps the binary's capability map. Would
  translate to a library call but the result is a CLI-introspection
  artifact with no downstream use.
- **`doctor`** — environment health-check; output is diagnostic
  human-readable text. Library callers typically have their own
  readiness checks.
- **`config`** — reads/writes user settings. Settings belong to the
  caller, not the library.

### Ambiguous (could translate; aspects worth discussing)

- **`apply` with multiple output writers** — currently emits stdout +
  optional side-effect files (trace, log, owners). Library consumers
  likely want a single `ApplyResponse` with fields for each artifact.
  `usecase.ApplyResponse.EvaluationData` is currently typed `any`
  (`internal/core/usecase/apply.go:32`) — a typed result would be
  sharper.
- **`diagnose explain`** — renders markdown/narrative. The
  library-shape could return the structured trace; the rendering
  would stay a separate concern.
- **`report`** / **`scorecard`** — compose existing evaluation output
  into reports. Library shape: return the composed structure, let
  callers render.
- **`exempt`, `bundle`, `attest`, `collect`, `verify` (evidence-archive)**
  — side-effect-heavy (filesystem writes). Library consumers want
  explicit opt-in rather than default side-effects.

---

## 5. Type inventory

### Typed primitives (already exported cleanly)

`internal/core/kernel/` — the canonical wrapper home:

| Type | Underlying | File |
|---|---|---|
| `ControlID` | string | `control_id.go:13` |
| `AssetType` | string | `asset_type.go:13` |
| `Vendor` | string | `vendor.go:11` |
| `ScopeTag` | string | `identity.go:16` |
| `AssetDomain` | string | `identity.go:8` |
| `PackName` | string | `identity.go:12` |
| `AWSAccountID` | string | `identity.go:19` |
| `AWSAccountARN` | string | `identity.go:22` |
| `ObservationSourceType` | string | `identity.go:25` |
| `ObjectPrefix` | string | `object_prefix.go:7` |
| `Digest` | string | `crypto.go:8` |
| `Signature` | string | `crypto.go:51` |
| `Schema` | string | `schema.go:6` |
| `StatementID` | string | `source_id.go:4` |
| `GranteeID` | string | `source_id.go:9` |
| `EncryptionAlgorithm` | string | `cryptography.go:10` |
| `OutputKind` | string | `kind.go:5` |
| `Duration` | `time.Duration` | `timeutil.go:25` |
| `TimeWindow` | struct | `timewindow.go:10` |
| `ControlClass` | int | `classification.go:8` |
| `NetworkScope` | int | `network_scope.go:10` |
| `PrincipalScope` | int | `principal_scope.go:10` |
| `TrustBoundary` | int | `trust_boundary.go:10` |
| `AirgapPolicy`, `BucketRef`, `NamespaceClaim`, `SanitizableMap`, `Sanitizer` (interface) | struct/interface | misc |

`internal/core/asset/`:

| Type | Underlying | File |
|---|---|---|
| `asset.ID` | string | `id.go:12` |
| `asset.Asset` | struct | `models.go:18` |
| `asset.Snapshot` | struct | `snapshot.go:22` |
| `asset.ExposureLifecycle` | struct | `lifecycle.go:12` |

`internal/core/controldef/`:

| Type | Role | File |
|---|---|---|
| `ControlDefinition` | Core control struct | `definition.go:32` |
| `Severity` | int enum | `severity.go:12` |
| `Classification` | string enum | `classification.go` |
| `ComplianceMapping` | `map[ComplianceFramework]string` | `definition.go` |
| `RemediationSpec`, `Exposure`, `Alternative`, `UnsafePredicate`, `PredicateRule` | struct types | various files |

`internal/core/evaluation/`:

| Type | Role | File |
|---|---|---|
| `Finding` | Per-violation record | `finding.go:18` |
| `Issue` | Consolidated finding group | `issue.go:24` |
| `ComplianceReport` | Top-level evaluation result | `audit.go:248` |
| `MatchedClause`, `Misconfiguration`, `Evidence`, `PostureDrift` | Finding sub-shapes | `finding.go` |

`internal/core/report/`:

| Type | Role | File |
|---|---|---|
| `report.Assessment` | Top-level **JSON-wire** shape for `apply` output | `models.go:47` |

`internal/app/contracts/`:

| Type | Role | File |
|---|---|---|
| `OutputFormat` | `text`/`json`/`sarif`/`markdown` enum | `format.go:4` |
| `ObservationRepository` (interface) | Loader port | `ports.go` |
| `ControlRepository` (interface) | Loader port | `ports.go` |
| `FindingMarshaler` (interface) | Writer port | `ports.go` |

### Primitive-obsession candidates (currently strings; wrapping would help)

These are strings today where a typed wrapper would prevent confusion
with other string IDs or enable compile-time validation:

1. **File paths (`ControlsDir`, `ObservationsDir`, `InputFile`,
   `TeamManifest`, `SARIFBaseline`, etc.)** — currently `string` in
   `Options` / `ApplyRequest`. A `ProjectPath` or path-type wrapper
   would let library callers distinguish user-supplied paths (need
   normalization) from already-normalized internal paths. Today
   `fsutil.CleanUserPath` is called ad hoc.
2. **Duration strings (`MaxUnsafeDuration`, `MaxUnsafeDurationStr`,
   SLA thresholds) — currently `string` in `ApplyRequest`, parsed to
   `kernel.Duration` later. Library callers should pass
   `kernel.Duration` or `time.Duration` directly; the string form is
   a CLI concession.
3. **RFC3339 timestamps (`NowTime` in `ApplyRequest`,
   `assertRecent`)** — currently `string`, parsed to `time.Time` at
   evaluation. Library shape should accept `time.Time` directly.
4. **Format strings (`ApplyRequest.Format`)** — currently `string`;
   `appcontracts.OutputFormat` already exists but isn't used in the
   `usecase` package. Tightening the type would prevent typos and
   enable switch-exhaustiveness checks.
5. **`ApplyResponse.EvaluationData any`** (`internal/core/usecase/apply.go:32`)
   — the result is opaque. A typed `*report.Assessment` (or a
   library-specific `ApplyResult`) would replace the `any`.
6. **Output-writer paths scattered across commands** — every
   output-producing command has its own `--output` flag as `string`.
   No unifying type.

### Types currently internal but stable (could be exposed cleanly)

- All of `kernel/` (pure value types, no impl leakage)
- `controldef.ControlDefinition`, `Severity`, `Classification`,
  `Alternative`
- `evaluation.Finding`, `Issue`, `ComplianceReport`, `MatchedClause`
- `asset.Asset`, `Snapshot`, `ID`
- `report.Assessment` (already serialized as JSON wire format)
- `contracts.OutputFormat`

### Types currently internal with active evolution (not yet stable for export)

- `internal/app/*` (78 packages) — application-orchestration types.
  Many are internal implementation details of CLI commands (options
  structs, DTO shapes, per-command repository interfaces). Exposing
  these would leak command-specific concerns into the library.
- `usecase.ApplyRequest.EvaluationData any` — the core library
  candidate but currently has an `any`-typed result field.
- Cobra-specific structs (`cmd/apply/Options`, `Deps`, `Builder`,
  `StandardIO`, `applyParams`) — these exist to translate CLI
  plumbing into core calls. Not library-shaped.

---

## 6. Apply command — deep dive

### CLI surface

**File**: `cmd/apply/cmd.go:109 NewApplyCmd(deps Deps) *cobra.Command`

**Help text synopsis** (from `cmd.go:115–153`):

> Apply executes control evaluation and produces safety findings.
>
> **Modes:**
> - *Default*: Evaluate observations against controls in a project directory.
> - *`--dry-run`*: Readiness checks only.
> - *`--profile`*: Evaluate a bundled observations file against a built-in control pack.

**Typical invocations:**

```
stave apply --controls ./controls --observations ./obs --format json
stave apply --dry-run
stave apply --profile aws-s3 --input observations.json --now 2026-01-15T00:00:00Z
```

**Flag surface** (`Options` at `cmd/apply/cmd.go:38, 66`; ~26 fields):

Shared (in `SharedOptions`):
- `--controls, -i` — `ControlsDir string` (default `controls`)
- `--observations, -o` — `ObservationsDir string` (default `observations`)
- `--max-unsafe` — `MaxUnsafeDuration string` (default from project config)
- `--now` — `NowTime string` (RFC3339)
- `--format, -f` — `Format string` (`text`/`json`/`sarif`; default `json`)

Apply-specific:
- `--dry-run` — readiness check only
- `--allow-unknown-input` — accept observations with unknown source types
- `--exemption-file` — path to exemption YAML
- `--acknowledgment-file` — path to acknowledgment YAML
- `--integrity-manifest`, `--integrity-public-key` — observation integrity
- `--profile, -p` — profile name (e.g., `aws-s3`); requires `--input`
- `--input` — observation bundle file (profile mode)
- `--bucket-allowlist` — filter to specific buckets
- `--include-all` — override default filtering
- `--trace-path` — emit per-clause trace to file
- `--sla-profile`, `--sla-profile-file`, `--sla-policy` — SLA overlay
- `--team-manifest` — ownership routing
- `--owner-filter` — filter by owner
- `--profile-files` — additional control overlays
- `--overlay-path` — bundled profile overlay
- `--show-suppressed` — include exempted findings
- `--assets-manifest` — override asset inventory
- `--history-dir` — posture-drift baseline
- `--new-only`, `--new-since` — filter to recent findings
- `--sarif-baseline` — baseline SARIF file for diff
- `--assert-recent` — bail if observations older than duration

Plus all global persistent flags from `cmd/root.go:23`.

### JSON output structure (`out.v0.1`)

Top-level shape per `internal/core/report/models.go:47 type Assessment`:

```json
{
  "schema_version": "out.v0.1",
  "kind": "ASSESSMENT",
  "status": "COMPLIANT" | "AT_RISK" | "NON_COMPLIANT",
  "run": { ... },          // evaluation.RunInfo
  "summary": { ... },      // evaluation.ComplianceSummary
  "risk_signals": [...],   // risk.ThresholdItems
  "findings": [...],       // remediation.Finding[]
  "chain_findings": [...], // risk.CompoundFinding[]
  "attack_stage_summary": { ... },  // map[stage]string
  "top_exposures": [...],  // risk.ExposureRank[]
  "issues": [...],         // evaluation.Issue[]
  "excepted_findings": [...],
  "acknowledged_findings": [...],
  "remediation_groups": [...],
  "skipped_controls": [...],
  "exempted_assets": [...],
  "coverage_posture": { ... },  // per-tool coverage stats
  "extensions": { ... }         // context_name, resolved_paths, git metadata
}
```

Per-finding fields (`internal/core/evaluation/finding.go:18`): `finding_id`,
`control_id`, `control_name`, `asset_id`, `asset_type`, `control_severity`,
`control_compliance`, `exposure`, `posture_drift`, `reasoning_trace`,
`alternatives`, `classification`, `scope_tags`, `remediation_context`,
`fix_plan`, `chain_membership`, SLA fields.

### Internal package path (typical `apply` invocation)

1. **`cmd/apply/cmd.go:NewApplyCmd`** builds the Cobra command from
   `Deps`.
2. **`cmd/apply/run.go` / `run_standard.go`** dispatches based on
   mode (`--dry-run`, `--profile`, or default).
3. **`cmd/apply/deps.go:84 (*Builder).Build`** assembles
   `appeval.ApplyDeps{Runner, Config}` via
   `appeval.BuildDependencies`.
4. **`internal/app/eval/workflow.go:90 (*AuditWorkflow).PerformAssessment(ctx, AssessmentConfig)`**
   is the core entry:
   - Calls `prepareAuditData` → loads controls + snapshots via
     `appcontracts.ControlRepository` + `appcontracts.ObservationRepository`
   - Calls `Evaluate(EvaluateInput{...})` → per-control predicate
     evaluation via `internal/core/evaluation/engine/`
   - Calls `enrichWithRiskReasoning` → chain detection + attack-stage
     summary
   - Annotates SLA deadlines via `evaluation.AnnotateFindingSLA`
   - Returns `(ComplianceReport, SecurityState, error)`
5. **`internal/app/eval/evaluation_output.go:OutputPipeline`**
   (constructed in `cmd/apply/run_evaluate.go`) takes the report
   through `EnrichFunc` → `FindingMarshaler.MarshalFindings` → stdout.

### Key types touched

- Input: `appeval.EvaluationPlan`, `appeval.AssessmentConfig`,
  `policy.ControlDefinition[]`, `asset.Snapshot[]`
- Output: `evaluation.ComplianceReport`, `evaluation.SecurityState`,
  surfaced as `report.Assessment` JSON
- Adapters in-flight:
  `appcontracts.ObservationRepository`/`ControlRepository`,
  `policy.PredicateEval`, `kernel.Sanitizer`, `ports.Digester`,
  `ports.Tracer`

### Existing `usecase.Apply` façade (under-utilized)

`internal/core/usecase/apply.go:14`:

```go
type ApplyRequest struct {
    ControlsDir, ObservationsDir, MaxUnsafeDuration, NowTime, Format,
    ExemptionFile, IntegrityManifest, IntegrityPublicKey, Profile, InputFile string
    DryRun, AllowUnknownInput, IncludeAll bool
    BucketAllowlist []string
}

type ApplyResponse struct {
    EvaluationData any         // ← opaque; candidate for typed replacement
    HasViolations  bool
    Warnings       []string
}

func Apply(ctx context.Context, req ApplyRequest, deps ApplyDeps) (ApplyResponse, error)
```

**This is the cleanest library-entry-point candidate for apply** —
but `cmd/apply/` doesn't currently route through it. The library
design likely wants to make `usecase.Apply` the canonical entry and
either (a) route the CLI through it or (b) accept that the CLI can
keep its richer path and the library wraps `usecase.Apply`.

---

## 7. Restructuring notes for cleaner library exposure

These commands are library-suitable but have specific entanglements
the library design should address.

### Apply — `EvaluationData any` in `ApplyResponse`

`internal/core/usecase/apply.go:32` types the result as `any`. Library
consumers pattern-match on the JSON shape. A typed
`*report.Assessment` (already serialized to JSON as `out.v0.1`) is
the obvious replacement. The restructuring is a one-line type change
plus updating `EvaluationRunnerPort.RunEvaluation` to return the
typed result.

### Apply — CLI path bypasses `usecase.Apply`

`cmd/apply/` calls `appeval.AuditWorkflow` directly, while `usecase.
Apply` exists but isn't wired. Either bring the CLI under `usecase.
Apply` (requires the options→request translation layer) or accept
that the library consumes `usecase.Apply` and the CLI is a richer
alternate path. The former is cleaner; the latter is lower-risk.

### Apply — rich CLI options don't map to `usecase.ApplyRequest`

The CLI `Options` struct has ~26 fields; `usecase.ApplyRequest` has
~13. Missing from the request: `TeamManifest`, `OwnerFilter`,
`ProfileFiles`, `OverlayPath`, `AssetsManifest`, `HistoryDir`,
`NewOnly`, `NewSince`, `SARIFBaseline`, `AssertRecent`, SLA fields,
`TracePath`. The library design needs to decide whether these are:
- Library features (extend `ApplyRequest`),
- CLI-only features (stay in `cmd/apply/` and never reach the library),
- Or split across multiple library calls (e.g., SARIF-baseline diff is
  a separate library function consuming `ApplyResponse`).

### Output writers — library returns values, CLI renders

Every output-producing command today emits to `stdout` via a
`FindingMarshaler`. Library consumers don't want stdout; they want
typed values. The `appcontracts.FindingMarshaler` interface belongs
to the CLI layer. The library should return `*report.Assessment` (or
equivalent) and let callers marshal to JSON/SARIF themselves — or
expose marshaling as separate helpers (`library.MarshalJSON(assessment)
→ []byte`).

### Side-effect commands — opt-in semantics

`exempt`, `bundle`, `attest`, `collect`, `forge`, `init`, `config`
write files as primary behavior. Library-ifying them requires
separating "compute the content" from "write it to disk." The pattern
would be: library returns bytes + suggested path; caller decides
whether to write.

### Dependency factories — wire-up contract

Today commands accept `compose.ObsRepoFactory` etc. The library
version needs to either:
- Provide default factory implementations as library exports (so the
  common case is zero-config), or
- Accept the factory interfaces as library parameters (flexible but
  verbose).

Probably both: default factories for the 90%-case, overridable for
custom storage / custom control sources.

### Ports package exposes implementation-layer types

`internal/core/ports/` contains `Clock`, `Digester`, `Tracer`
interfaces. Library consumers shouldn't have to satisfy these for
every call. Default implementations (`ports.RealClock{}`,
`crypto.NewHasher()`) already exist; the library should accept them
as defaults when the consumer doesn't care.

### Internal packages under `internal/` are not importable externally

Go's `internal/` package rule means nothing under
`internal/` is reachable from outside `github.com/sufield/stave`.
The library design must either:
- Move library-facing types **out of internal/** into a new exported
  package (e.g., `pkg/stavelib/` or root-level `stave` package).
- Or re-export them through a shim package that sits above
  `internal/`.

This is the single most concrete structural requirement: today the
types and functions library consumers want are all in `internal/`,
which means the library can't expose them without either moving or
re-exporting them.

### Doctor / capabilities / completion — CLI-only by design

These commands produce CLI artifacts (shell completion, environment
reports). They don't need library equivalents; the library design
should explicitly exclude them to prevent accidental scope creep.

---

## Related prior art

- **`CLAUDE.md` § "CLI Command Conventions"** — documents the
  `PreRunE`/`RunE` split, standardized flag names, help-text
  standard, and command-shape conventions that the survey relies on.
- **`docs/product/architecture.md` § "The platform split"** — states
  the hexagonal layering: core provides primitives, apps compose
  them. The library is the formal shape of "app consumes core
  primitives." The survey shows 78 `internal/app/*` packages today
  that act as pre-library orchestration.
- **`docs/product/architecture.md` § "stave-explorer" + "bucket-intent"**
  — the two monorepo-level prototypes that consume Stave's JSON
  output via shell-out. They're effectively forced into that shape
  today because `internal/core/usecase/` isn't importable from
  outside the Stave module. A real library would let them import
  instead.

---

## Open questions for the library-design iteration

Not answered in this survey; listed here so the design iteration can
pick them up:

- **Scope of v1 library surface.** All of §4 "Suitable"? Only apply +
  the usecase-covered set (apply/gate/fix/verify/trace)? Only apply?
- **Package location.** `pkg/stave/`, root-level `stave/` (alongside
  the existing `cmd/stave/` main), or a separate `stavelib` module?
- **`any`-typed `ApplyResponse.EvaluationData`.** Replace with
  `*report.Assessment`, or keep opaque and add typed accessors?
- **CLI-library alignment.** Rewrite `cmd/apply/` through
  `usecase.Apply`, or accept divergent paths?
- **Marshaling.** Library returns typed values only, or exposes
  `MarshalJSON(v)`/`MarshalSARIF(v)` helpers?
- **Version + compatibility.** The library is v1 from day one; what
  does stability mean for `Finding`/`Issue`/`Assessment` shape
  changes that the current out.v0.1 schema already tolerates?
