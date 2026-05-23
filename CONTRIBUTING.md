# Contributing to Stave

Thank you for considering contributing to Stave. This document explains how to set up your development environment, run tests, and submit changes.

## Development Environment

### Option 1 — Coder workspace (recommended)

Launch a pre-configured workspace with the right Go toolchain,
Steampipe, every test fixture, and pre-built `stave`/`stave-mcp`
binaries already in place:

```bash
# From a checkout of this repo:
coder templates push stave --directory stave-workspace
coder create my-stave --template stave
```

Inside the workspace:

```bash
make test-unit   # < 2 min, the dev-loop test tier
make lint        # golangci-lint (pre-installed)
make build       # rebuild ./stave after changes
make mcp         # rebuild ./stave-mcp after changes
```

See [`stave-workspace/README.md`](./stave-workspace/README.md) for
what the image includes, how to customize it, and the honest
caveats (no code-server, no AWS creds, no extra Steampipe plugins).
The workspace is the lowest-friction contributor path: no Go install
to manage, no toolchain-version drift between contributors, no
"works on my machine" — the image pins everything.

### Option 2 — Local setup

If you'd rather work in your own environment:

**Prerequisites**

- Go 1.26.3 or later
- golangci-lint (optional, for linting)
- Make (for convenience targets)

**Setup**

```bash
# Clone the repository
git clone https://github.com/sufield/stave.git
cd stave

# Verify Go version
go version

# Download dependencies
go mod download

# Build the binary
make build

# Run tests
make test
```

The local path also works for adopters who only want the CLI on
their host (see [README Option 3](./README.md#option-3--local-install-contributors-and-power-users)
for `go install` instructions that skip the clone).

## Running Tests

```bash
# Fast dev loop — unit tests only, skips e2e / golden / profile suites.
# Designed to finish under 30 seconds.
make test-unit

# Full local suite — runs everything assuming goldens are current.
# Use this before opening a PR if you want a final local check.
make test

# CI entry point — regenerates goldens fresh, then runs the full suite.
# Goldens are regenerated in the CI workspace and discarded; nothing is
# committed back. You should not need to run this locally.
make test-ci

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
make test-coverage

# Run a specific test
go test -v -run TestEvaluator ./internal/core/...

# Run startup benchmark (informational performance budget)
go test -run '^$' -bench BenchmarkCLIStartupHelp -benchmem ./cmd
```

Startup target for lightweight commands is approximately `<500ms` (see `BenchmarkCLIStartupHelp` in `cmd/startup_benchmark_test.go`).

### Why three test targets

Adding a control changes the policy fingerprint embedded in 2000+
golden fixtures. Regenerating those goldens locally on every control
addition is slow churn that adds no signal — the diffs are catalog
growth, not behavior. So:

- `make test-unit` is the dev feedback loop. It uses `go test -short`
  and excludes `./e2e/`, so any test that gates on `testing.Short()`
  (e2e, profile, fixture-binary determinism) self-skips.
- `make test-ci` is what CI runs. It regenerates goldens fresh and
  then runs the full suite, so behavior regressions are still caught
  but fingerprint churn never blocks a PR.
- `make test` is unchanged — full suite, assumes goldens are current.

If you write a new test that builds the CLI binary, executes it, or
compares against a golden, gate it with `if testing.Short() { t.Skip(...) }`
so it stays out of the dev fast path.

### Parallelizing slow packages

When a package's serial test cost starts dominating CI wall time,
add `t.Parallel()` to every Test function in the package. The
mechanical edit is scripted:

```bash
make parallelize PKG=./internal/core/enginetest
```

The script (`scripts/add-parallel.sh`) inserts `t.Parallel()` as
the first line of every `Test*` function and skips files that
mutate process-wide state (`t.Setenv`, `os.Setenv`, `os.Chdir`)
to avoid races. The original 6-package rollout (commit `4c7170cf0`)
took enginetest from 349s → 33s standalone (10.6×).

After running, verify with `go test -race ./<package>` to confirm
no races surfaced.

### Test Prerequisites

E2E tests (`make e2e`, which drives `go test ./e2e/...`) require:

- **jq** — JSON processor for comparing evaluation output
- **diff** — standard Unix diff for golden-file comparison
- **bash** — example invocations use bash-specific features

These are not needed for unit tests (`make test`), only for E2E validation.

### Regenerating fixture goldens

When a change modifies control YAML (metadata, predicate, add/remove
control) the e2e goldens under `testdata/e2e/*/expected.*` and
`testdata/e2e/*/golden.json` go stale. Regenerate them with:

```bash
make regenerate-goldens
```

The tool:

- Walks every fixture under `testdata/e2e/`.
- Picks the correct invocation shape (default `apply`, `command.txt`
  override, or profile-style `apply --profile aws-s3/hipaa`).
- Writes the updated goldens (`expected.out.json`,
  `expected.summary.json`, `expected.findings.count`, `expected.exit`,
  `expected.input_hashes.json`, `expected.source_evidence.json`,
  `expected.out.sarif`, `golden.json`).
- Prints a report bucketed as CLEAN / FINGERPRINT-ONLY /
  METADATA-ONLY / BEHAVIORAL / MIXED.

Flags are passed via the `ARGS` variable:

```bash
make regenerate-goldens ARGS="-dry-run"            # preview, no writes
make regenerate-goldens ARGS="-filter s3-public"   # limit to regex match
```

Interpreting the diff categories:

| Category | What it means | Safe to commit? |
|---|---|---|
| CLEAN | Fixture output unchanged. | Yes — nothing to commit. |
| FINGERPRINT-ONLY | Only `run.policy_fingerprint` shifted (a new control joined the catalog and changed the per-profile hash; detection behavior is identical). | Yes. |
| METADATA-ONLY | Only projected metadata changed: `control_name`, `control_description`, `control_compliance*`, `remediation.*`, `exposure.*`. Detection identical. | Yes. |
| BEHAVIORAL | Findings identity, count, severity, evidence, or summary changed. Detection behavior shifted. | **Investigate first.** Confirm the shift matches the intended change. |
| MIXED | Both metadata and behavioral paths diffed in the same fixture. | **Investigate first.** |

The target does not run as part of `make check` or CI. It is a
developer tool — run it explicitly, review the report, then commit.
Automatic regeneration is what masked the drift-cleanup series bugs.

## Code Quality

Before submitting changes, ensure your code passes all checks:

```bash
# Run all checks (format, vet, lint, test)
make check

# Individual checks
make fmt     # Format code with gofmt
make vet     # Run go vet
make lint    # Run golangci-lint (if installed)
```

For Go modernization and dead-code cleanup requirements, follow `gofixer.md` before opening a PR.

## Code Style

Stave follows standard Go conventions:

- Format code with `gofmt` (run `make fmt`)
- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use meaningful variable and function names
- Write Godoc comments for all exported identifiers
- Start comments with the identifier name (e.g., `// Evaluator computes...`)

CLI output and command UX conventions are documented in `docs/cli-style-guide.md`.

### CLI Command Conventions

New commands must use the `NewCmd()` factory pattern:

```go
func NewCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "mycommand",
        Short: "...",
        RunE:  run,
    }
    cmd.Flags().StringVar(&opts.Flag, "flag", "default", "help text")
    return cmd
}
```

Do not use package-level `var Cmd = &cobra.Command{...}` with `init()` for new commands. Existing commands that use this pattern should not be retrofitted unless they are being substantially modified for other reasons.

### Package Organization

```
internal/
├── domain/     # Core business logic, no external dependencies
├── app/        # Use case orchestration
└── adapters/   # Input/output adapters (JSON, YAML loaders)
```

- Keep domain logic in `internal/core` without I/O concerns
- Use interfaces (ports) for external dependencies
- Implement adapters in `internal/adapters`

## Submitting Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-sarif-output`
- `fix/episode-duration-calculation`
- `docs/improve-readme`

### Commit Messages

Write clear commit messages:

```
Add SARIF output format support

- Implement SARIF 2.1.0 writer in adapters/output/sarif
- Add --format flag to apply command
- Update documentation with SARIF examples
```

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Run `make check` to verify all checks pass
4. Push your branch and open a pull request
5. Describe what the PR does and why
6. Link any related issues

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] Code is formatted (`make fmt`)
- [ ] No vet warnings (`make vet`)
- [ ] Lint passes (`make lint`)
- [ ] New features have tests
- [ ] Documentation updated for all user-visible changes (required)
- [ ] If CLI commands/flags/help changed, regenerate CLI reference docs (`cd ../publisher && make docs-gen`)

### Docs-as-Code rules

Documentation is treated as a first-class artifact:

1. User-visible behavior changes must ship with docs updates in the same PR.
2. CLI usage reference generation is owned by sibling `../publisher` tooling, not hand-edited per-command pages.
3. Stave CI runs link checks; publisher workflows own docs generation.

## Adding Controls

To add new controls:

1. Create a YAML file in the appropriate pack directory
2. Use DSL version `ctrl.v1`
3. Define clear `unsafe_predicate` conditions
4. Add per-control tests in the YAML's own `tests:` block (run via `stave test`) and cover the predicate logic at the call site under `internal/core/...`

Example control:

```yaml
dsl_version: ctrl.v1
id: CTL.EXP.DURATION.002
name: Descriptive Name
description: What this control checks.
type: unsafe_duration
unsafe_predicate:
  any:
    - field: "properties.some_field"
      op: "eq"
      value: true
```

Note: Control IDs must follow the format `CTL.<DOMAIN>.<CATEGORY>.<SEQ>` where:
- DOMAIN: EXP, ID, TP, PROC, or META
- CATEGORY: STATE, DURATION, RECURRENCE, AUTHZ, JUSTIFICATION, OWNERSHIP, or VISIBILITY
- SEQ: 3-digit sequence number

## Secret Scanning

The repository uses [gitleaks](https://github.com/gitleaks/gitleaks) to prevent accidental credential leaks. Configuration is in `.gitleaks.toml` at the repo root.

### Local Setup (pre-commit)

```bash
# Install pre-commit (once)
pip install pre-commit

# Install hooks (once, from repo root)
cd /path/to/bizacademy
pre-commit install

# Run manually against all files
pre-commit run --all-files
```

### Run gitleaks Directly

```bash
# Install gitleaks: https://github.com/gitleaks/gitleaks#installing
gitleaks detect --source . --config .gitleaks.toml
```

### Allowlist

Known false positives (AWS example keys, Visa test numbers, educational fixtures) are allowlisted in `.gitleaks.toml`. If you add test fixtures containing synthetic credentials, either:

1. Use clearly fake formats (e.g., `AKIAIOSFODNN7EXAMPLE`, `sk_live_EXAMPLE_NOT_A_REAL_KEY`)
2. Add a path-scoped allowlist entry in `.gitleaks.toml`

### CI

The `secret-scan` GitHub Actions workflow runs gitleaks on every push and PR to `main`.

## Synthetic Test Data

All AWS account IDs, ARNs, and bucket names under `testdata/` and `case-studies/` are synthetic placeholders. They do not correspond to real AWS accounts. See `testdata/README.md` for details.

## Reporting Bugs

When filing a bug report, include a minimal, deterministic reproduction. See the [Bug Reproduction Guide](docs/contrib/bug-repro-guide.md) for how to write one, and the [Bug Reproduction Template](docs/contrib/bug-repro-template.md) for a copy-paste starting point.

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Provide minimal reproduction steps for bugs

## Scope note

Stave MVP scope is AWS S3 public exposure only.

## Vocabulary

Stave uses one canonical term per concept in user-facing surfaces
(CLI help, docs, MCP descriptions, external articles): `control`,
`finding`, `catalog`, `evaluation`, `verdict`, `chain`, `observation`.
The canonical → deprecated mapping, the "why control not invariant"
rationale, and the carve-outs where `invariant` deliberately stays
(internal type names, the solver-import JSON contract, research and
explanation docs) are in [`TERMINOLOGY.md`](./TERMINOLOGY.md). The
Docs Drift CI check enforces the phrase-level renames on the
user-facing surfaces.
