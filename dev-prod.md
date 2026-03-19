# Dev/Prod Architecture Analysis

An assessment of where Stave stands on the "Atomic Core vs. Workflow Shells"
spectrum, what the codebase already does well, where real coupling remains,
and what to do about it.

---

## 1. Current State

### 1.1 What already exists

Stave already has most of the structural separation the proposal describes.
The codebase is not a monolithic CLI — it is a layered hexagonal architecture
with a clean domain core.

| Layer | Location | LOC (non-test) | Purpose |
|-------|----------|---------------:|---------|
| Domain | `internal/domain/` | 13,005 | Evaluation engine, asset models, predicates, policies |
| Application | `internal/app/` | ~4,000 | Use-case orchestration (eval, diagnose, validate) |
| Adapters | `internal/adapters/` | ~3,500 | I/O: control loaders, observation parsers, output formatters |
| Platform | `internal/platform/` | ~1,500 | Logging, crypto, filesystem, state |
| CLI | `cmd/` | 17,136 | Two binaries, command handlers, flag parsing |
| **Total** | | **~39,000** | |

**Separate binaries already exist:**

```
cmd/stave/main.go      →  cmd.Execute()      →  prod binary (10.1 MB)
cmd/stave-dev/main.go  →  cmd.ExecuteDev()    →  dev binary  (10.8 MB)
```

**Production guard already exists** (`cmd/prodguard.go`):
- Detects production via `STAVE_ENV` or project context
- Hard-blocks destructive commands (`prune`)
- Warns on dev commands running against production

**DI ports already exist** (`internal/app/contracts/ports.go`):
- `ObservationRepository` — loads snapshots
- `ControlRepository` — loads controls
- `FindingMarshaler` — formats output
- `EnrichFunc` — traces, exposure, remediation
- `ContentHasher`, `PackRegistry`, `ResultLoader`

**Domain interfaces already exist** (14+ in `internal/domain/`):
- `ports.Clock`, `ports.Digester`, `ports.Verifier`
- `kernel.Sanitizer` (ID, Path, Value)
- `asset.AssetPredicate` — scope filtering
- `engine.strategy` — evaluation strategy selection
- `remediation.Specialist` — pluggable remediation planners

**Controls are already declarative data** — 43 YAML files using `ctrl.v1`
schema with `unsafe_predicate` expressions (`any`/`all` + field operators).
Adding a new control is a YAML file, not a code change. This is the OCP
goal already achieved.

**Extraction code already removed** — 7,190 lines moved to
`stave-extractor/` (separate module, `github.com/sufield/stave-extractor`).

**Dependencies are already minimal** — `go.mod` has 6 direct dependencies:

| Dependency | Purpose | Weight |
|-----------|---------|--------|
| cobra | CLI framework | Light |
| pflag | Flag parsing | Light |
| yaml.v3 | Control parsing | Light |
| jsonschema/v6 | Schema validation | Light |
| samber/lo | FP utilities | Light |
| x/sync | Concurrency primitives | Light |

No cloud SDKs. No Terraform parsers. No HTTP clients. The binary is
air-gapped by design.

### 1.2 Where the collision actually lives

Despite the clean layering, there are real coupling points that prevent
the full "Atomic Core + Thin Shells" split:

#### Problem 1: Shared `internal/` between both binaries

Both `stave` and `stave-dev` compile from the same module. Go's linker
includes all transitively reachable code. The dev binary is only 760 KB
larger (7.3% overhead), which means nearly all code ships in both binaries.

This is architecturally fine (the domain code is shared intentionally), but
it means the prod binary includes compiled dev-command code even though the
`stave` entry point never calls `WireDevCommands()`. Go's dead-code
elimination handles most of this, but the symbol table still carries it.

#### Problem 2: `cmd/` is too large (17,136 lines)

The command layer is larger than the domain layer. Most of this is in the
prod commands (`apply`: 2,374, `enforce`: 2,653, `diagnose`: 2,645,
`initcmd`: 2,545, `prune`: 2,839), not dev commands. The bloat is in
_workflow orchestration_, not _dev tooling_.

Command-level line counts:

| Package | Lines | Type |
|---------|------:|------|
| `cmd/enforce/` | 2,653 | Prod (7 subcommands) |
| `cmd/prune/` | 2,839 | Mixed (6 prod + 1 dev) |
| `cmd/diagnose/` | 2,645 | Prod (4 subcommands) |
| `cmd/initcmd/` | 2,545 | Prod (init, generate, config, alias) |
| `cmd/apply/` | 2,374 | Prod (apply, validate, verify) |
| `cmd/bugreport/` | 672 | Dev |
| `cmd/securityaudit/` | 346 | Dev |
| `cmd/doctor/` | 150 | Dev |
| `cmd/*.go` (root infra) | 1,405 | Shared |

Dev-only commands total ~1,168 lines. The other 15,968 lines are prod or
shared. Moving dev commands to a separate repo saves < 7% of `cmd/`.

#### Problem 3: No `pkg/` — the engine cannot be imported externally

The evaluation engine lives in `internal/domain/evaluation/engine/`. The
`internal` import barrier means no external tool (not even `stave-extractor`)
can call `engine.Runner.Evaluate()` directly. This is intentional for now
(API stability), but blocks the "Library-First Core" vision.

#### Problem 4: Dev/prod commands share test helpers

Test files in `cmd/` reference both prod and dev commands (e.g.,
`help_groups_test.go` tests both `TestRootHelpGroupsAssigned` and
`TestDevHelpGroupsAssigned`). Splitting into separate repos means
duplicating test infrastructure or creating a shared test module.

---

## 2. Assessment of Proposed Actions

### 2.1 "Stop trying to make one binary do both"

**Status: Already done.** Two binaries exist. The CI environment sees only
`stave`. The dev binary adds doctor, trace, lint, fmt, scaffolding,
bug-report, security-audit, graph visualization.

**Remaining gap:** Both binaries are built from one `go.mod`. A true
separation would mean `stave-dev` is a separate module that imports a
published `stave` library. This is a major versioning commitment that is
premature for a v0.0.3 project.

**Recommendation:** Keep the single-module dual-binary approach. The 760 KB
overhead is not meaningful. The production guard provides the safety boundary.
Revisit at v1.0 when API stability matters.

### 2.2 "Achieving OCP: Invariants as Data or Plugins"

**Status: Already done.** Controls are YAML files with a declarative
predicate language (`ctrl.v1`). The engine evaluates arbitrary field paths
against arbitrary JSON properties. Adding 1,000 new controls requires zero
Go code changes.

The control schema supports:
- `unsafe_predicate` with `any`/`all` combinators
- Field operators: `eq`, `ne`, `in`, `missing`, `contains`, `prefix`
- Dot-notation field paths against arbitrary JSON
- Per-control `max_unsafe_duration` overrides
- Severity classification and remediation guidance

**No CEL/JSONata needed.** The existing predicate language is purpose-built
for safety invariants and is simpler than a general expression language.
Adding a general-purpose expression engine would increase attack surface and
binary size for no benefit.

### 2.3 "Kill the Speculative Bloat"

**Status: Partially done.** Extraction code is removed. What remains in
`cmd/` is not speculative — it is the production workflow:

- `validate` → input correctness before evaluation
- `apply` → core evaluation (the pipe processor)
- `diagnose` → explain unexpected results
- `enforce` → CI gates, baselines, fix loops, diffs
- `snapshot` → retention management for observation directories
- `init` → project scaffolding (generates `.stave/` structure)

The dev-only commands (doctor, trace, lint, fmt, graph, bug-report,
security-audit) are genuinely useful for control authors and already
isolated behind `WireDevCommands()`.

**The "Pipe Test":** `stave apply` already works as a pipe processor:

```bash
stave apply --controls ./ctl --observations ./obs --format json > out.json
stave apply --controls ./ctl --observations - < obs.json  # stdin
```

Commands that fail the pipe test (`init`, `doctor`, `bug-report`) are
scaffolding and diagnostic tools, not core evaluation. They are already
separated by the prod/dev split.

### 2.4 "Inversion of Control for logging"

**Status: Already done.** The domain layer (`internal/domain/`) has zero
logging dependencies. It communicates through return values and the
`ports.Clock`, `ports.Digester`, and `kernel.Sanitizer` interfaces. The
application layer wires loggers. The CLI layer configures output format.

The trace system (`internal/trace/`) is an explicit data structure (not
log calls) that the CLI can render as JSON or human text. This is cleaner
than an Observer pattern because traces are part of the evaluation result,
not side-channel output.

### 2.5 "Move shared code to `pkg/`"

**Not recommended yet.** Exposing a public Go API (`pkg/core/`) creates a
backwards-compatibility contract. At v0.0.3, the evaluation engine API is
still evolving (recent additions: exemption handling, safety envelopes,
integrity checking). Premature publication would either freeze the API or
break downstream consumers.

**When to do it:** After v1.0, extract `internal/domain/evaluation/engine/`
and `internal/domain/` into a `pkg/stave/` package with a stable public API.
Version it with Go module semantics.

---

## 3. What Actually Needs Work

The codebase does not have the problems the proposal assumes. It already has
clean layering, DI ports, declarative controls, separate binaries, and a
production guard. Here is what actually needs attention:

### 3.1 `cmd/` size reduction (real bloat)

The 17K lines in `cmd/` include substantial workflow orchestration that
belongs in `internal/app/`. Commands should be thin wrappers (parse flags →
call app service → format output).

**Candidates to push down:**

| Command | Current cmd/ LOC | Likely app/ LOC after |
|---------|----------------:|---------------------:|
| `enforce/fix/` | 601 | ~100 in cmd, ~500 in app/workflow |
| `enforce/gate/` | 360 | ~80 in cmd, ~280 in app/workflow |
| `enforce/graph/` | 328 | ~60 in cmd, ~268 in app/graph |
| `prune/snapshot/` | 786 | ~120 in cmd, ~666 in app/retention |
| `diagnose/artifacts/` | 714 | ~100 in cmd, ~614 in app/artifacts |

This would make command handlers < 150 lines each (flag parsing + service
call + output), pushing business logic into the testable app layer.

### 3.2 Build-tag isolation for dev-only code

Currently, both binaries compile the same `cmd/` package. Dev-only packages
(`cmd/bugreport/`, `cmd/doctor/`, `cmd/securityaudit/`) are imported by
`commands_dev.go` but compiled into both binaries.

**Fix:** Add `//go:build stavedev` to `commands_dev.go` and all dev-only
packages. The `stave-dev` Makefile target already exists — add `-tags stavedev`
to its build flags. This gives true dead-code elimination for the prod binary.

```makefile
build:
    $(GOBUILD) $(LDFLAGS) -o stave ./cmd/stave

build-dev:
    $(GOBUILD) $(LDFLAGS) -tags stavedev -o stave-dev ./cmd/stave-dev
```

Expected prod binary reduction: ~500 KB (the bug-report, doctor,
security-audit, and graph packages).

### 3.3 Guard against `internal/domain/` importing adapters

The domain layer is currently clean (zero adapter imports), but there is no
automated check. Add a boundary test:

```go
// TestDomainDoesNotImportAdapters prevents coupling regressions.
func TestDomainDoesNotImportAdapters(t *testing.T) {
    // Walk internal/domain/**/*.go, parse imports, reject
    // any path containing "/adapters/", "/platform/", "/cli/"
}
```

This is the successor to the now-removed
`TestApplyCommandsDoNotImportExtractors` — generalized to protect the entire
domain layer.

### 3.4 Enforce the "under 500 lines" contract for command handlers

Add a test that fails if any single command handler file exceeds 500 lines.
This prevents workflow creep back into `cmd/`:

```go
func TestCommandHandlersAreUnder500Lines(t *testing.T) {
    // Walk cmd/**/*.go, exclude test files, count lines
}
```

---

## 4. Architecture Comparison

| Aspect | Proposed | Current Stave | Gap |
|--------|----------|---------------|-----|
| Separate binaries | `stave` + `stave-dev` | `cmd/stave/` + `cmd/stave-dev/` | None |
| Core as library | `pkg/core/` | `internal/domain/` (not exported) | Intentional — premature to export at v0.0.3 |
| DI ports | Interface-based | `internal/app/contracts/ports.go` | None |
| Declarative controls | CEL/JSONata | `ctrl.v1` YAML with field predicates | Simpler is better — no gap |
| Production guard | N/A | `cmd/prodguard.go` (env + context detection) | None |
| Extraction out of core | Separate repo | `stave-extractor/` (just completed) | None |
| Observer pattern | Interface-based logging | Domain has zero log deps; trace is data | Cleaner than Observer |
| No cloud SDKs | Required | 6 lightweight deps, zero cloud SDKs | None |
| `cmd/` < 500 lines | Target | 17,136 lines | Real gap — push logic to `internal/app/` |
| Build-tag isolation | N/A | Not used for dev/prod split | Achievable with `//go:build stavedev` |

---

## 5. Action Items (Priority Order)

### Immediate (this cycle)

1. **Domain boundary test** — Add `TestDomainLayerBoundary` to prevent
   `internal/domain/` from importing adapters, platform, or CLI packages.
   ~50 lines, catches regressions permanently.

### Next cycle

2. **Build-tag dev isolation** — Tag `commands_dev.go` and dev-only command
   packages with `//go:build stavedev`. Saves ~500 KB in prod binary and
   prevents accidental dev-code execution.

3. **Push workflow logic to `internal/app/`** — Start with `enforce/fix/`
   and `enforce/gate/` (largest command handlers). Target: no command handler
   file over 200 lines.

### v1.0 timeframe

4. **Export public API** — Extract `internal/domain/` into `pkg/stave/` with
   a versioned, stable API. This enables external consumers (stave-extractor,
   third-party tools) to import the evaluation engine directly.

5. **Separate `stave-dev` module** — If binary size or dependency isolation
   becomes a real concern, move dev commands to a separate Go module that
   depends on the published `pkg/stave/` API.

---

## 6. What NOT to Do

- **Do not add CEL/JSONata.** The `ctrl.v1` predicate language is simpler,
  safer (no Turing-complete expressions), and already covers all current
  control needs. A general expression engine adds attack surface and
  dependency weight.

- **Do not split into separate repos yet.** Single-module dual-binary is
  the right trade-off at v0.0.3. Repo splits add CI complexity, version
  coordination, and import path management overhead.

- **Do not create a `pkg/` directory yet.** Exporting an API is a
  one-way door. Wait until the domain model is stable (post-v1.0).

- **Do not rewrite in Rust/C++.** The Go binary is 10 MB, starts in
  milliseconds, and has zero runtime dependencies. Language migration
  is not justified by any current constraint.

- **Do not introduce an Observer pattern for logging.** The current
  approach (domain returns data, app layer enriches, CLI formats) is
  cleaner and more testable than callback-based observation.
