# Contributing to Stave

Thank you for considering contributing to Stave. This document explains how to set up your development environment, run tests, and submit changes.

## Development Environment

### Prerequisites

- Go 1.26.1 or later
- golangci-lint (optional, for linting)
- Make (for convenience targets)

### Setup

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

## Running Tests

```bash
# Run all tests
make test

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
make test-coverage

# Run a specific test
go test -v -run TestEvaluator ./internal/domain

# Run startup benchmark (informational performance budget)
go test -run '^$' -bench BenchmarkCLIStartupHelp -benchmem ./cmd/stave/cmd
```

Startup target for lightweight commands is approximately `<500ms` (see `BenchmarkCLIStartupHelp` in `cmd/stave/cmd/startup_benchmark_test.go`).

### Test Prerequisites

E2E tests (`scripts/e2e.sh`, `scripts/e2e-counterfactual.sh`) require:

- **jq** — JSON processor for comparing evaluation output
- **diff** — standard Unix diff for golden-file comparison
- **bash** — scripts use bash-specific features (process substitution)

These are not needed for unit tests (`make test`), only for E2E validation.

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

### Package Organization

```
internal/
├── domain/     # Core business logic, no external dependencies
├── app/        # Use case orchestration
└── adapters/   # Input/output adapters (JSON, YAML loaders)
```

- Keep domain logic in `internal/domain` without I/O concerns
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
- Add --format flag to evaluate command
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
4. Add tests in `internal/domain/control_test.go`

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
