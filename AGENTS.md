# AGENTS.md — Stave CLI Codex

Rules for AI agents working on this codebase. These patterns were established through 60+ refactorings over 2 months. Violating them creates regressions.

## Architecture

Stave uses hexagonal architecture enforced by compile-time tests in `internal/app/architecture_core_isolation_test.go` and `internal/app/architecture_dependency_test.go`.

### Layer Rules

```
cmd/           CLI boundary: Cobra commands, flag parsing, dependency wiring
  |
  v
adapters/      Infrastructure: filesystem, YAML loading, JSON output, git
  |
  v
app/           Application services: orchestration, pipelines, workflows
  |
  v
core/          Domain model: ZERO external imports (no os, no fmt, no net)
```

### Do

- Place domain types in `internal/core/`. Domain types must have zero imports from `app/`, `adapters/`, `cmd/`, or `platform/`.
- Place application orchestration in `internal/app/`. App services import `core/` and `app/contracts` ports.
- Place infrastructure implementations in `internal/adapters/`. Adapters implement port interfaces from `app/contracts`.
- Wire adapters to app services in `cmd/` via `deps.go` files and `cmdutil/compose/infra.go`.
- Use `internal/platform/` for OS-level utilities (crypto, filesystem, logging, shell).

### Internal Encapsulation

- All complex security logic and data structures MUST reside in `internal/`.
- The `cmd/` package is a "Thin Adapter." It handles only flag parsing and calling `app/` or `core/` services.
- If a domain model, evaluation type, or security logic is proposed for `cmd/`, it is a hexagonal violation. Move it to `core/` or `app/`.
- This prevents "Logic Leakage" and keeps the binary's entry point clean and auditable.

### Don't

- Import `adapters/` from `app/` or `core/`. This is the #1 hexagonal violation.
- Import `cobra`, `os.Exit`, `fmt.Printf`, `fmt.Println`, `os.Stderr`, `os.Stdout` from `core/` or `app/`.
- Import `net/http`, `os/exec`, `database/sql`, or `flag` from test files in `core/` or `app/`.
- Create packages in `pkg/`. Everything lives under `internal/`.
- Add pass-through "workflow" or "bridge" packages between layers. If a package only forwards calls, delete it.
- Move domain models, evaluation types, or security logic into `cmd/`. This is logic leakage.

## Command Structure

Every CLI command follows this file convention:

| File | Purpose |
|------|---------|
| `cmd.go` | Command construction, Cobra registration, `Long` help text |
| `run.go` | Execution logic (thin: construct request, call app service, format output) |
| `options.go` | Flag struct + `Prepare(cmd)` method (resolve defaults, normalize, validate) |
| `output.go` | Rendering (text, JSON, SARIF) |
| `deps.go` | Dependency wiring |

### Do

- Put all flag validation and config resolution in `PreRunE` via `opts.Prepare(cmd)`.
- Keep `RunE` thin — delegate to `app/` or `core/` services.
- Set `SilenceUsage: true` and `SilenceErrors: true` on every command.
- Include purpose, inputs, outputs, exit codes, and examples in the `Long` help string.
- Use stable flag names: `--controls/-i`, `--observations/-o`, `--format/-f`, `--now`, `--quiet`, `--sanitize`.

### Don't

- Parse flags in `RunE`. All flag parsing belongs in `PreRunE`.
- Import domain types in `cmd.go`. The `cmd.go` file constructs the command; `run.go` uses domain types.
- Create new subcommands when a flag mode suffices (e.g., `apply --dry-run` not `plan`).
- Skip `Prepare(cmd)` and put validation inline in RunE.

## Domain Vocabulary

These terms are final. The renames are done. Use the canonical term.

| Canonical Term | Rejected Alternatives (never use) |
|---|---|
| `control` | invariant, rule, check |
| `asset` | resource |
| `finding` | issue, violation, result |
| `exemption` | ignore, suppress, skip |
| `sanitize` | redact, scrub |
| `drift` | delta, change |
| `ExposureWindow` | Episode |
| `ExposureLifecycle` | Timeline |
| `AuditScope` | ScopeFilter |
| `Assessor` | Runner (engine) |
| `PolicyInspector` | PackRunner |
| `GovernanceResolver` | Evaluator |
| `DiagnosticSuite` | CheckSuite |
| `AuditWorkflow` | EvaluateRun |
| `DiagnosticEngine` | Run (diagnose) |
| `PolicyTracer` | trace Runner |
| `AccessSummary` | Facts |
| `StatementAssessment` | risk.Audit |
| `report` (package) | safetyenvelope |
| `attestation` (package) | verify |
| `compliance` (package) | hipaa |
| `collector` | accumulator |
| `mapper` | translator |

### Don't

- Introduce new terms without checking the table above.
- Use the rejected alternatives in code, comments, commit messages, or documentation.
- Name a file `types.go`. Name it after the primary type it contains.

## Type Safety

### Do

- Use typed domain IDs: `kernel.ControlID`, `asset.ID`, `kernel.AssetType`, `kernel.Vendor`, `schemas.Kind`, `ui.OutputFormat`.
- Validate at parse boundaries via `UnmarshalText`/`UnmarshalJSON`/`UnmarshalYAML` on domain types.
- Use constructors (`NewControlID`, `NewDigest`, `NewAssetType`) that enforce invariants.
- Use `outcome.Status` for compliance status, `controldef.Severity` for severity — the canonical types.

### Don't

- Use raw `string` for IDs, statuses, severities, output formats, or schema kinds. These have typed equivalents.
- Create type aliases that duplicate a canonical type. Import the canonical type directly.
- Validate at evaluation time what can be validated at parse/load time ("parse, don't validate").

## Error Handling

### Do

- Wrap errors with `fmt.Errorf("verb phrase: %w", err)` — "load project config", "parse control".
- Use `ui.UserError` for user-caused errors (exit code 2) and `ui.WithHint` for fix suggestions.
- Use sentinel errors from package-level `var` declarations for known failure modes.
- Panic for programming errors (nil registry, lifecycle contract violations) — not `error`.
- Return `error` for operational failures (file not found, parse failures, network errors).

### Don't

- Return `error` from constructors that can only fail due to programming mistakes. Panic instead ("design errors out").
- Use `os.Exit` anywhere except `cmd/stave/main.go` and the signal handler.
- Map unknown errors to exit code 2. Unknown errors are exit code 4 (internal).
- Create error messages without a verb phrase opening ("load project config" not "project config error").

## Logging

### Do

- Use `slog.Debug` or `slog.Info` for all diagnostic output in `app/` and `core/`.
- Write progress indicators (spinners, bars) to stderr only. Suppress when stderr is not a TTY.
- Use structured fields: `slog.String("control_id", id)`, not interpolated strings.

### Don't

- Use `fmt.Print*` or `log.*` in production code outside `cmd/`.
- Log in `core/`. Domain code is pure — it returns values, not side effects.
- Write to stdout for anything except command output. Diagnostics go to stderr.

### Logging exceptions (these bypass slog intentionally)

- Signal handler (`executor.go`): runs outside Cobra lifecycle
- Error rendering (`executor_errors.go`): runs after command teardown
- First-run hint (`executor_firstrun.go`): runs before bootstrap
- No-project hint (`executor_firstrun.go`): runs after command teardown
- Alias resolution (`runtime_helpers.go`): runs before bootstrap
- Bug report inspector (`bugreport/inspect_run.go`): diagnostic tool output

## Testing

### Do

- Use `google/go-cmp` with `testutil.AssertEqual` for struct comparisons.
- Use fluent test builders from `internal/testutil` for constructing Assessor, Control, and ExposureLifecycle fixtures.
- Use `testscript` for behavioral CLI tests in `testdata/script/`.
- Use golden file pattern: commit expected outputs, diff generated output byte-for-byte.
- Use `NewTestCatalog()` for test control registries — not `init()` globals.
- Use `--now` for deterministic time in CLI tests.
- Enable the race detector (`-race` flag).

### Don't

- Use `time.Now()` directly. Inject time via `core/ports.Clock` or function parameters. The architecture test enforces this.
- Create test mocks for the database — there is no database. Stave is offline-first.
- Skip the `--allow-unknown-input` flag for custom observation types in E2E tests.

## File Organization

### Do

- Name files after the primary type they contain (`assessor.go`, `finding.go`, `control_definition.go`).
- Merge anemic single-type files into their logical neighbor.
- Split god files along SRP boundaries (detection, diagnosis, remediation — not input, process, output).

### Don't

- Name files `types.go`, `utils.go`, `helpers.go`, or `common.go`.
- Create a file with fewer than ~20 lines of logic. Merge it.
- Keep backward-compatibility aliases or re-exports. Delete them immediately.

## Refactoring

### Do

- Follow Strangler Fig for package extraction: new package first, then rewire consumers, then delete old package.
- Follow Mikado Method for cross-cutting renames: leaf changes first, then propagate inward.
- Enable one linter per commit with all violations fixed in the same commit.
- Delete dead code immediately. Run `deadcode` to find it.
- Rename files when the primary type they contain is renamed.

### Don't

- Keep old code "for backward compatibility." This codebase has no external consumers — delete immediately.
- Leave TODO comments for removed code. If it's removed, it's gone.
- Create transition periods with both old and new APIs. Cut over atomically.

## Build

- `make build` (not bare `go build`) — schemas must be synced first.
- `make test` runs with `-race` and `-tags stavedev`.
- `make e2e` runs against the built binary.
- `make fuzz` runs fuzz tests on security-critical parsers.

## Identity: Stave Is a Formal Proof System

Stave is NOT a cloud tool. It is a **policy evaluation engine for JSON-represented infrastructure**. The engine knows nothing about AWS, GCP, Azure, or any specific cloud service. It evaluates predicates against `properties.*` paths on assets with open-ended `type` and `vendor` strings.

### Proven with zero engine changes — 233 controls, 28 domains, 5 vendors

10 compliance framework profiles, all implemented via YAML controls + compliance tags:

| Profile | Framework | Tagged Controls |
|---|---|---|
| `--profile hipaa` | HIPAA §164.312 | 64 |
| `--profile cis-aws-v3.0` | CIS AWS Foundations v3.0 | 56 |
| `--profile soc2` | SOC 2 Trust Service Criteria | 101 |
| `--profile pci-dss-v4.0` | PCI-DSS v4.0 | 57 |
| `--profile nist-800-53` | NIST SP 800-53 Rev 5 | 57 |
| `--profile fedramp` | FedRAMP Moderate | 58 |
| `--profile gdpr` | GDPR | 36 |
| `--profile ffiec` | FFIEC | 29 |
| `--profile iso-27001` | ISO 27001:2022 | 24 |
| `--profile nist-csf-2.0` | NIST CSF 2.0 | 20 |

### Terminology

Use "controls" everywhere. Never use "invariants" for security controls.
The compliance catalog files (`docs/{framework}/`) use `controls:` as the
top-level YAML key, `existing_control:` for mapped entries. The term
"invariant" is only used in the Go code sense (type invariants at
construction time via `NewControlID`, `NewDigest`, etc.).

### Adding a new domain requires

1. Control YAML files in `controls/{domain}/`
2. Property namespace in `docs/observation-contract.md`
3. Pack entry in `internal/builtin/pack/embedded/index.yaml`
4. Embed glob in `internal/controldata/embed.go`
5. Profile constant in `cmd/apply/profile.go` (optional)
6. E2E test fixture with golden output
7. INCOMPLETE control for missing extractor data

### Adding a new domain does NOT require

- Engine changes (`internal/core/`)
- Application layer changes (`internal/app/`)
- Adapter changes (`internal/adapters/`)
- CEL evaluator changes (`internal/cel/`)
- New Go types, interfaces, or packages

## Multi-Domain Data Modeling

### Do

- Give each domain its own property namespace: `properties.storage.*`, `properties.identity.*`, `properties.dns.*`.
- Use `kind` as the discriminator within a namespace (e.g., `storage.kind: "bucket"`, `identity.kind: "user"`).
- Share property names across vendors when semantics align (e.g., `storage.access.public_read` works for both S3 and GCS).
- Use vendor-specific fields when semantics diverge (e.g., `storage.controls.uniform_access_enabled` for GCS only).
- Model each real-world resource as its own asset type — DNS records are `dns_record`, not `s3_bucket_reference`.
- Keep vendor in the `vendor` field on the asset, not in the property namespace.

### Don't

- Mix data from different real-world resources in one asset. DNS records and S3 buckets are separate assets with separate property namespaces.
- Put vendor names in property paths. Use `storage.access.public_read`, not `storage.aws.s3.public_read`.
- Create vendor-specific control packs when a vendor-agnostic control works. DNS dangling reference detection works for any DNS provider.
- Add cloud provider SDKs to Stave. Extractors are external — Stave defines the contract, clients build the extractors.
- Create `Provider` enums or restrict the `vendor` field. Vendor is an open string by design.

## Observation Contract

Stave's multi-domain capability is a **schema specification**, not code. The observation contract (`docs/observation-contract.md`) tells extractor authors what properties to populate. Controls evaluate those properties. If an extractor provides insufficient data, INCOMPLETE controls fire rather than giving false compliant verdicts.

### Do

- Document every new property namespace in `docs/observation-contract.md` before writing controls that use it.
- Add an INCOMPLETE control for every new domain (e.g., `CTL.DNS.INCOMPLETE.001`).
- Write controls against the documented contract, not against vendor API responses.

### Don't

- Write controls that assume vendor-specific JSON structure. Controls evaluate normalized properties.
- Skip the observation contract doc when adding a domain. The contract is how clients know what to extract.

## Policy Creation

### Do

- Define new security checks as YAML controls in `controls/` following the ctrl.v1 DSL.
- Use `make forge` to scaffold new controls with E2E test fixtures.
- Accompany every new control with at least two observation snapshots: one that triggers the finding and one that confirms evaluation works.
- Place controls in domain-specific subdirectories: `controls/s3/`, `controls/iam/`, `controls/gcs/`, `controls/dns/`.
- Run `make sync-controls` after adding controls to update the embedded pack.

### Don't

- Hardcode security detection logic in Go. Controls are declarative YAML, not imperative Go.
- Create controls without a `remediation.action` field. Every control must have a remediation path.
- Create controls without test fixtures. Untested controls are invisible regressions.
- Place controls directly in `internal/controldata/embedded/`. That directory is build-generated from `controls/`.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Security-audit gating threshold exceeded |
| 2 | Input/user error |
| 3 | Violations found |
| 4 | Internal error |
| 130 | SIGINT |
