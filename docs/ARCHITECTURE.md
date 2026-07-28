# Architecture

Stave follows Hexagonal Architecture (ports and adapters). The dependency rule is enforced by `internal/app/architecture_dependency_test.go`.

## Layer Map

```
cmd/                 CLI entry points (Cobra). Extracts flags, wires adapters, delegates to app layer.
internal/
  core/              Domain model. Zero external dependencies. Business rules and types.
    usecase/         Use-case orchestration (Gate, Apply, Fix, Verify, Trace) + port interfaces.
    evaluation/      Evaluation engine, findings, remediation, risk scoring.
    controldef/      Control definition types and parsing.
    asset/           Asset, Snapshot, Timeline, Delta.
    kernel/          Shared value types (ControlID, AssetType, Schema, Duration).
    ports/           Domain-level abstractions (Clock, Digester, Verifier).
  app/               Application services. Orchestrates domain + adapters.
    contracts/       App-layer port interfaces (ObservationRepository, ControlRepository).
    eval/            Evaluation pipeline (BuildDependencies, EvaluateRun, OutputPipeline).
    ...              One package per feature (diagnose, explain, fix, lint, securityaudit).
  adapters/          Infrastructure implementations. Talks to filesystem, AWS, git, etc.
    controls/        Control loaders (builtin embedded YAML, filesystem YAML).
    observations/    Observation file loaders.
    output/          Output formatters (JSON, text, SARIF, Markdown).
    baseline/        Baseline comparison adapter.
    gate/            CI gating adapter (findings counter, baseline comparer).
    ...              One package per external concern.
  platform/          OS-level utilities (crypto, fsutil, logging). No domain knowledge.
  cli/               CLI infrastructure (UI runtime, progress bars, error formatting).
```

## Dependency Rule

Dependencies point inward. Outer layers depend on inner layers, never the reverse.

```
cmd/  --->  adapters/  --->  app/  --->  core/
                |                          ^
                |      (implements)        |
                +--- ports/interfaces -----+
```

- `cmd/` depends on `adapters/`, `app/`, and `core/`
- `adapters/` depends on `app/contracts` (port interfaces) and `core/`
- `app/` depends on `core/`
- `core/` depends on nothing — it is the innermost layer

Enforced by `internal/app/architecture_dependency_test.go`.

## Where to Find Things

| Looking for... | Look in... |
|---|---|
| What the tool does (use cases) | `internal/core/usecase/` |
| How evaluation works | `internal/core/evaluation/engine/` |
| Control definitions and parsing | `internal/core/controldef/` |
| Port interfaces (domain) | `internal/core/usecase/` (use-case ports) and `internal/core/ports/` (Clock, Digester) |
| Port interfaces (app) | `internal/app/contracts/` |
| Adapter implementations | `internal/adapters/` |
| CLI command registration | `cmd/commands.go` (`WireCommands()`) |
| Dependency wiring | `cmd/cmdutil/compose/infra.go` (`Provider`) |

## Design Invariant: Pipeline Processing Order

The evaluation pipeline processes stages in this order:

1. Snapshot ingestion (observation schema normalization)
2. Fact extraction (boolean field computation by collectors)
3. CEL predicate evaluation per control per asset
4. Chain detection via threshold logic (DetectChains)
5. Graph construction via pre/postcondition matching
6. Datalog transitive reachability (Soufflé)
7. Distance classification (partial conjunction evaluator)
8. Implicit dependency annotation
9. Choke point analysis + severity elevation

This order is the triangular matrix order from the Axiomatic
Design analysis: each stage consumes only the outputs of
earlier stages, never later ones. Reordering stages violates
the Independence Axiom (Axiom 1) and introduces circular
dependencies that break deterministic evaluation.

Reference: `docs-internal/architecture/axiomatic-design.md`

## Design Rationale: Three Reasoning Engines

Stave uses three reasoning engines:

| Engine | Computation class | What it answers |
|---|---|---|
| CEL | Local predicate (per-resource) | "Is this resource misconfigured?" |
| Datalog (Soufflé) | Transitive closure (global graph) | "Can this role reach that resource?" |
| Z3 (SMT) | Satisfiability (semantic equivalence) | "Is this control version equivalent to the previous?" |

Each engine serves a distinct functional requirement that the
other two cannot satisfy. The Information Axiom (Axiom 2)
confirms this is the minimum set — removing any engine loses
a capability no other engine can provide.

## Command Trace: `stave apply`

1. `cmd/stave/main.go` -- entry point
2. `cmd/root.go` -- creates Cobra root, calls `WireCommands()`
3. `cmd/commands.go` -- registers `apply.NewApplyCmd(provider)`
4. `cmd/apply/cmd.go` -- defines flags, `PreRunE` resolves config, `RunE` calls `runApply()`
5. `cmd/apply/run.go` -- extracts `cobraState` (Cobra-free boundary), dispatches by mode
6. `cmd/apply/deps.go` -- `Builder.Build()` assembles adapters from factories
7. `internal/app/eval/build.go` -- `BuildDependencies()` assembles evaluation pipeline
8. `internal/app/eval/workflow.go` -- `AuditWorkflow.PerformAssessment()` loads artifacts, calls engine
9. `internal/core/evaluation/engine/assessor.go` -- engine `Assessor` (core domain evaluation)
10. `internal/app/eval/evaluation_output.go` -- `OutputPipeline.Run()` marshals and writes results
