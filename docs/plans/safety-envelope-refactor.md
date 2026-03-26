status: done
# Safety Envelope Refactor Plan

## Problem Statement

The safety classification is split across isolated subsystems. The main
`apply` command cannot return `BORDERLINE` status because
`risk.ComputeItems` is never called in that path — `ClassifySafetyStatus`
receives hardcoded `nil` for upcoming risks (`evaluation_run.go:97`).
Meanwhile, the same risk computation runs correctly in `enforce gate`,
`prune upcoming`, and `hygiene`. The pieces exist but aren't wired together.

## Goals

1. One place answers "safe, borderline, or unsafe": the evaluation result.
2. No command infers safety via `len(findings)` or ad-hoc `if` trees.
3. Every safety result includes status + violations + at-risk signals +
   control pack version/hash.
4. `out.v0.1` JSON schema remains valid. New fields are additive.
5. Response logic (what to *do* about a result) lives in domain, not in
   command handlers.

## Current State

| Concept | Location | Status |
|---------|----------|--------|
| `SafetyStatus` (SAFE/BORDERLINE/UNSAFE) | `pkg/alpha/domain/evaluation/result.go:50-68` | Defined, BORDERLINE unreachable in apply |
| `ClassifySafetyStatus(violations, upcoming)` | `pkg/alpha/domain/evaluation/result.go:59` | Called with `nil` for upcoming |
| `risk.ComputeItems(ThresholdRequest)` | `pkg/alpha/domain/evaluation/risk/upcoming.go:165` | Used in gate/prune/hygiene, NOT in apply |
| `ThresholdItems.HasAnyRisk()` | `pkg/alpha/domain/evaluation/risk/upcoming.go` | Never reached from apply |
| Guidance/response mapping | `cmd/apply/guidance.go`, `cmd/apply/output.go` | Command-specific, not reusable |
| Control pack hash | `engine/runner.go:225` via `computePackHash()` | Populated correctly in RunInfo |
| Extensions/metadata | `evaluation/metadata.go:49` | Git, paths, pack info — already in output |
| Enrichment pipeline | `internal/app/eval/evaluation_run.go:66` | Engine → classify → enrich → marshal |
| Envelope assembly | `internal/safetyenvelope/types.go` | Wire DTOs for schema output |

## Phase 1: Wire Risk Into Apply (fix the gap)

**Goal**: Make `BORDERLINE` reachable. No new types, no structural changes.

### Changes

**`internal/app/eval/evaluation_run.go`** — Compute upcoming risk before
classifying safety status.

```
Before:
  status := evaluation.ClassifySafetyStatus(len(result.Findings), nil)

After:
  upcoming := risk.ComputeItems(risk.ThresholdRequest{
      Controls:                controls,
      Snapshots:               snapshots,
      GlobalMaxUnsafeDuration: cfg.MaxUnsafeDuration,
      Now:                     result.Run.Now,
      PredicateParser:         cfg.PredicateParser,
      PredicateEval:           cfg.CELEvaluator,
  })
  status := evaluation.ClassifySafetyStatus(len(result.Findings), upcoming)
```

The `controls`, `snapshots`, `cfg` are all already in scope at this call
site. No new dependencies required.

### Acceptance

- `ClassifySafetyStatus` receives real `ThresholdItems`.
- Apply command returns `BORDERLINE` when violations == 0 but risk items
  exist.
- `cmd/apply/output.go` already handles non-Safe status correctly (prints
  hints, exit 3). Verify BORDERLINE triggers the same path.
- All existing E2E golden tests pass unchanged (BORDERLINE only triggers
  when no violations exist, so findings-based tests are unaffected).
- Add test: two snapshots where an asset is currently unsafe but below
  threshold → status == BORDERLINE.

## Phase 2: Bundle Status Into Evaluation Result

**Goal**: Callers receive status from the result itself, not from a
separate classification call.

### Changes

**`pkg/alpha/domain/evaluation/result.go`** — Add fields to `Result`:

```go
type Result struct {
    // ... existing fields ...
    SafetyStatus SafetyStatus       `json:"safety_status"`
    AtRisk       risk.ThresholdItems `json:"at_risk,omitempty"`
}
```

**`pkg/alpha/domain/evaluation/engine/runner.go`** — Compute risk and
status inside `Evaluate()`, populate the new fields in `buildResult()`.

**`internal/app/eval/evaluation_run.go`** — Read status from result
instead of computing it externally:

```
Before:
  status := evaluation.ClassifySafetyStatus(len(result.Findings), upcoming)
  return result, status, nil

After:
  return result, result.SafetyStatus, nil
```

**`internal/safetyenvelope/types.go`** — Add `SafetyStatus` and `AtRisk`
to the `Evaluation` envelope DTO so they appear in `out.v0.1` output.
These are additive fields — existing consumers that don't read them are
unaffected.

### Acceptance

- `Result.SafetyStatus` is set by the engine, not by callers.
- `ExecuteAndReturn` signature can drop the separate `SafetyStatus`
  return value (or keep it for backward compat, reading from result).
- JSON output includes `"safety_status"` and `"at_risk"` fields.
- E2E golden files updated to include the new fields.

## Phase 3: Extract Response Policy Into Domain

**Goal**: Response logic (what to *do* about each status) is reusable
across commands, not duplicated in `cmd/apply/guidance.go`.

### Changes

**New file: `pkg/alpha/domain/evaluation/response.go`**

```go
type ResponseAction struct {
    Severity ActionSeverity  // pass, warn, fail
    Hints    []string
}

type ResponsePolicy struct {
    StrictBorderline bool // treat BORDERLINE as fail in strict CI
}

func (p ResponsePolicy) Decide(status SafetyStatus) ResponseAction {
    switch status {
    case StatusSafe:
        return ResponseAction{Severity: ActionPass}
    case StatusBorderline:
        if p.StrictBorderline {
            return ResponseAction{Severity: ActionFail, Hints: borderlineHints}
        }
        return ResponseAction{Severity: ActionWarn, Hints: borderlineHints}
    case StatusUnsafe:
        return ResponseAction{Severity: ActionFail, Hints: unsafeHints}
    }
}
```

**`cmd/apply/guidance.go`** — Delegate to `ResponsePolicy.Decide()`
instead of inlining the status-to-action mapping.

**`cmd/enforce/gate/`** — Use the same policy for gate enforcement
decisions.

### Acceptance

- `cmd/apply/guidance.go` calls domain response policy, not inline logic.
- Gate enforcement and apply share the same decision function.
- `--strict-borderline` flag (or equivalent) available for CI pipelines
  that want BORDERLINE to fail.
- No new CLI flags required in phase 3 itself — the policy defaults to
  current behavior (BORDERLINE → warn).

## Phase 4: Control Catalog API

**Goal**: Single API for discovering, filtering, and inspecting controls.
Feeds doc generation and IDE tooling.

### Changes

**New file: `pkg/alpha/domain/policy/catalog.go`**

```go
type Catalog struct {
    controls []ControlDefinition
    byID     map[kernel.ControlID]*ControlDefinition
}

func NewCatalog(controls []ControlDefinition) *Catalog
func (c *Catalog) List() []ControlDefinition
func (c *Catalog) Get(id kernel.ControlID) (*ControlDefinition, bool)
func (c *Catalog) Filter(tags ...string) []ControlDefinition
func (c *Catalog) PackHash(h ports.Digester) kernel.Digest
```

Wire `ControlLoader.LoadControls` → `NewCatalog()` in the app layer.
Engine receives `catalog.List()` instead of raw slices.

### Acceptance

- One constructor, one lookup, one filter API.
- `engine.Runner.Controls` populated via `catalog.List()`.
- `computePackHash` delegates to `catalog.PackHash()`.
- Existing tests pass — the catalog is a thin wrapper, not a behavior
  change.

## Phase 5: Auto-Generate Control Docs

**Status: Complete.**

**Goal**: Control reference docs generated from the catalog (single
source), not hand-maintained.

### Implementation

**Tool: `internal/tools/gencontroldocs/main.go`**

- Loads all built-in controls via `builtin.Registry` with alias resolver
- Constructs a `policy.Catalog` for sorted, indexed access
- Generates `docs/controls/reference.md` with:
  - Pack hash for auditability
  - Severity and domain summary tables (sorted alphabetically)
  - Per-control sections: ID, name, description, severity, type, domain,
    compliance mappings, remediation action
- Deterministic output: controls sorted by ID, compliance keys sorted,
  summary tables sorted alphabetically
- `-check` mode exits 1 if output is stale (CI integration)

### Makefile Targets

```
make docs-controls         # generate docs/controls/reference.md
make docs-controls-check   # exit 1 if reference.md is stale
```

### Acceptance (verified)

- `make docs-controls` generates control reference from the catalog.
- `make docs-controls-check` detects stale output deterministically.
- Adding a new control YAML automatically appears in generated docs
  after running `make docs-controls`.

## Implementation Status

All phases are complete.

| Phase | Scope | Commit | Status |
|-------|-------|--------|--------|
| 1 | Wire risk into apply | `5ed0b31ac` | Done |
| 2 | Bundle status in result | `5ed0b31ac` | Done |
| 3 | Extract response policy | `cd4588b5d` | Done |
| 4 | Control catalog API | `29660b5b4` | Done |
| 5 | Doc generation | `a679b5dbf` | Done |

## Out of Scope

- Renaming `SAFE`/`BORDERLINE`/`UNSAFE` to `INSIDE`/`BOUNDARY`/`OUTSIDE`.
  Current names are established, tested, and clear.
- Renaming "control" to "invariant". The terminology migration to
  "control" was completed March 2026 (GLOSSARY.md). "Invariant" is the
  conceptual term for external audiences only.
- New `internal/domain/safety/` package hierarchy. The existing domain
  lives at `pkg/alpha/domain/` and the evaluation subsystem is already
  well-structured there. Adding a parallel hierarchy creates confusion.
- Schema version bump to `out.v0.2`. New fields are additive and
  backward-compatible within `out.v0.1`.
- Diagnosis and verification subsystem changes. These consume evaluation
  types and will benefit from Phase 2 automatically.
