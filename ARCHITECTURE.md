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
    ...              One package per feature (diagnose, explain, fix, lint, prune, securityaudit).
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

```
core/  -->  app/  -->  adapters/  -->  cmd/
  ^                       |
  |       (implements)    |
  +--- ports/interfaces --+
```

- `core/` must not import `app/`, `adapters/`, or `cmd/`
- `app/` must not import `adapters/` or `cmd/` (except `app/contracts` which defines ports)
- `adapters/` must not import `cmd/`

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

## Command Trace: `stave apply`

1. `cmd/stave/main.go` -- entry point
2. `cmd/root.go` -- creates Cobra root, calls `WireCommands()`
3. `cmd/commands.go` -- registers `apply.NewApplyCmd(provider)`
4. `cmd/apply/cmd.go` -- defines flags, `PreRunE` resolves config, `RunE` calls `runApply()`
5. `cmd/apply/run.go` -- extracts `cobraState` (Cobra-free boundary), dispatches by mode
6. `cmd/apply/deps.go` -- `Builder.Build()` assembles adapters from factories
7. `internal/app/eval/build.go` -- `BuildDependencies()` assembles evaluation pipeline
8. `internal/app/eval/evaluation_run.go` -- `EvaluateRun.Execute()` loads artifacts, calls engine
9. `internal/core/evaluation/engine/runner.go` -- `Runner.Evaluate()` (core domain evaluation)
10. `internal/app/eval/evaluation_output.go` -- `OutputPipeline.Run()` marshals and writes results
