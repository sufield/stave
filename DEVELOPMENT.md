# Stave Development Guide

Internal reference for contributors and AI agents. Read this
before working on the codebase.

CLAUDE.md covers CLI rules, data formats, and command conventions.
This file covers everything else a developer needs: vocabulary,
architecture, make targets, testing patterns, tooling, and
recurring tasks.

---

## Vocabulary

These terms are enforced. Using the wrong term is a review rejection.

| Correct | Incorrect | Why |
|---------|-----------|-----|
| control | invariant, rule, check | A control is the unit of evaluation |
| finding | violation, alert, issue | A finding is what a control produces |
| catalog | rule set, rule base | The catalog is the collection of controls |
| `stave apply` | `stave scan`, `stave evaluate` | The command is `apply` |
| `make gencontrol` | `make forge` | Scaffolds a new control YAML |
| `--eval-time` | `--now` | Evaluation reference timestamp flag |
| observation | snapshot (ambiguous) | An observation is a captured state |
| domain | service (in control YAML) | 86 domains, not AWS service names |
| `internal/core` | `internal/domain` | Renamed long ago; `stale-terminology-check` enforces |

---

## Architecture

Hexagonal architecture. Dependency direction is enforced by
depguard (golangci-lint) and boundary tests.

```
cmd/                    CLI boundary — cobra commands, flag parsing, wiring
internal/
  cli/                  CLI utilities (ui, errors, runtime helpers)
  core/                 Domain — pure business logic, ZERO infrastructure imports
    kernel/             Shared primitives (ControlID, AssetID, Digest, etc.)
    evaluation/         Evaluation engine, compliance logic
    report/             Output models (Assessment, Attestation, Readiness)
    controldef/         Control definition model
    asset/              Asset model
    predicate/          Predicate types
    taxonomy/           Vocabulary, Classifier
    sir/                Stave Intermediate Representation
    sirfacts/           SIR fact projectors
    ports/              Port interfaces (Clock, Verifier)
    schemaval/          Pre-flight validation types
    ... (25 packages)
  app/                  Use cases — orchestration layer (65+ packages)
    eval/               Evaluation orchestration
    fix/                Remediation loop
    attestation/        Before/after comparison
    readiness/          Pre-flight assessment
    ...
  adapters/             Infrastructure — implements ports (25+ packages)
    acknowledgment/     Acknowledgment config loader (YAML)
    artifacts/          Build artifact persistence
    aws/                AWS SDK adapters
    awsmeta/            Botocore service model metadata reader
    baseline/           Baseline comparison
    cel/                CEL predicate compiler + evaluator
    compliance/         Compliance framework YAML parser
    controls/           Control YAML parser + builtin loader
    coverage/           Coverage analysis (embedded alternative inventories)
    doctor/             Environment readiness checks
    evaluation/         Evaluation artifact JSON loader
    evidence/           Portable evidence bundle (tar.gz for air-gap GRC)
    exemption/          Exemption management
    govulncheck/        Vulnerability scanner (os/exec wrapper)
    graph/              Control/asset graph builder
    integrity/          Snapshot integrity verification
    observations/       Observation JSON loader + integrity
    output/             Output rendering (JSON, text, SARIF, reports)
    predicate/          Predicate evaluation adapters
    report/             Report generation adapters
    sirbridge/          Platform-specific SIR adapter wiring
    sla/                SLA policy loader (embedded YAML)
    telemetry/          Audit trail writer (audit_trace.json)
  contracts/            Schema validation, security contracts
    schema/             JSON schema validators (embedded)
    validator/          Report validators
    security/           Security contracts
  tools/                Development-time tooling (16 packages)
    gencontrol/         Control YAML scaffolder
    gencontroldocs/     Control reference generator
    gencommanddocs/     CLI command reference generator
    gendatalogdocs/     Datalog relations reference generator
    genmethodologycoverage/ Methodology coverage docs
    regengoldens/       Golden file regenerator
    semantic-diff/      Z3 differential harness
    triage/             AWS feature triage
    quarterly/          Quarterly audit orchestrator
    compliance-diff/    Framework differ
    auditreport/        Go best-practices audit report
    goroutinescan/      Goroutine analysis
    genassetschemas/    Asset schema generator
    ccmbackfill/        CCM backfill tool
    scope-classifier/   Scope classification
    taxonomytagger/     Taxonomy auto-tagger
pkg/stave/              Public API facade
reasoning/
  souffle/iam/          Datalog rules + schema (IAM effective access)
  souffle/discovery/    Datalog chain discovery engine
```

### Dependency Rules (depguard enforced)

```
core/       → stdlib only (no adapters, no cmd, no AWS)
app/        → core/ (defines interfaces for outer layers)
adapters/   → core/, app/ (implements port interfaces)
cmd/        → everything (wiring layer)
```

Specific enforcements in `.golangci.yml`:

| Rule | Scope | Blocks |
|------|-------|--------|
| `headless-core` | Everything except `cmd/`, `cliflags/`, `cmdctx/` | cobra, pflag, cliflags, cmdctx |
| `core-no-aws` | `internal/core/**` | AWS adapter imports |
| `gaps-facade-only` | `cmd/gaps/**` | All `internal/**` (must use `pkg/stave`) |
| `readiness-facade-only` | `cmd/readiness/**` | All `internal/**` (must use `pkg/stave`) |

Boundary tests (import-graph assertions at test time):
- `internal/app/architecture_core_isolation_test.go`
- `internal/app/architecture_dependency_test.go`
- `internal/app/status/boundary_test.go`
- `internal/core/report/boundary_test.go`
- `cmd/facade_ratchet_test.go`
- `cmd/gaps/architecture_test.go`
- `cmd/readiness/architecture_test.go`
- `cmd/score/architecture_test.go`

---

## Make Targets

### Build

| Target | What It Does |
|--------|-------------|
| `make build` | Build production `stave` binary (syncs schemas/controls/alternatives first) |
| `make build-dev` | Build dev binary with `-tags stavedev` (includes dev-only commands) |
| `make mcp` | Build `stave-mcp` server binary |
| `make install` | Install binary to `GOPATH/bin` |
| `make clean` | Remove build artifacts |

### Testing Pyramid

| Target | Scope | Speed |
|--------|-------|-------|
| `make test-fast` | `-short` flag, skips e2e/profile/golden | < 30s |
| `make test-pkg PKG=./path/...` | Single package, no sync | Seconds |
| `make test-integration` | `internal/...` + `cmd/apply/...` + `cmd/evaluate/...` | Minutes |
| `make test-e2e` | Binary-driven e2e + testscript | Minutes |
| `make test` | Full suite with `-race`, `-parallel 16`, `-timeout 30m` | ~10 min |
| `make test-ci` | Regenerate goldens + full suite | ~15 min |
| `make test-shard SHARD=N` | Reproduce CI shard 0-3 locally | Varies |
| `make test-compliance` | Metadata linter + testscript with coverage | Minutes |
| `make test-coverage` | Full suite with coverage HTML | Minutes |
| `make mcp-test` | MCP server protocol tests | Seconds |
| `make script-test` | Testscript behavioral CLI tests | Minutes |
| `make bench` | Performance benchmarks (engine eval at 10k assets) | Minutes |

### Fuzzing

| Target | What It Does |
|--------|-------------|
| `make fuzz` | Native Go fuzz (30s per target, 9 targets) |
| `make fuzz-cel` | Gosentry fuzz: CEL compiler |
| `make fuzz-snapshot` | Gosentry fuzz: snapshot parser |
| `make fuzz-iam` | Gosentry fuzz: IAM policy resolver (grammar mode) |
| `make fuzz-all` | All gosentry targets |
| `make fuzz-coverage` | Gosentry coverage reports |
| `make fuzz-install` | One-time gosentry build |

### Linting & Code Quality

| Target | What It Does |
|--------|-------------|
| `make lint` | golangci-lint v2.11.3 |
| `make lint-fix` | Auto-format (gofmt only) |
| `make lint-debt` | Ratcheted wrapcheck debt metric |
| `make fmt` | Format code |
| `make vet` | `go vet` |
| `make tidy` | `go mod tidy` |
| `make imports` | Auto-fix import grouping (goimports) |
| `make imports-check` | Check imports without modifying |
| `make gofixer` | Full Go modernization workflow (go fix + deadcode + lint + test) |
| `make deadcode-check` | Unreachable exported functions |
| `make check-unsafe-writes` | Forbid raw `os.Create`/`os.WriteFile` on user paths |
| `make refactor-scan` | List Go modernization candidates |
| `make refactor-scan-check` | Burn-down gate for modernization |
| `make audit` | Go best-practices baseline report |
| `make audit-check` | Verify baseline matches source |

### Golden File Management

Two golden families:

1. **In-process goldens** (small set under `internal/.../testdata/`):
   regenerated by `UPDATE_GOLDEN=1 go test`.
2. **E2E fixture goldens** (2687 fixtures under `testdata/e2e/`):
   regenerated by the `regengoldens` tool.

| Target | What It Does |
|--------|-------------|
| `make regenerate-goldens` | Batch-regenerate e2e fixture goldens, categorized diff report |
| `make regenerate-goldens-ci` | Same + exit non-zero on BEHAVIORAL/MIXED diffs |
| `make regenerate-goldens-strict` | + encoding verification |
| `make golden-update-all` | Regenerate all in-process goldens |
| `make golden-update PKG=...` | Regenerate in-process goldens for one package |
| `make golden-one PKG=... RUN=...` | Regenerate a single in-process golden test |
| `make golden-fixture FILTER=...` | Regenerate e2e fixture goldens matching regex |

Golden diff categories (from `regengoldens`):
- **CLEAN**: no changes
- **FINGERPRINT-ONLY**: only hash/fingerprint changed — safe to commit
- **METADATA-ONLY**: only metadata changed — safe to commit
- **BEHAVIORAL**: detection behavior shifted — investigate before committing
- **MIXED**: both metadata and behavioral — investigate

### Doc Generation

| Target | What It Does |
|--------|-------------|
| `make docs-controls` | Control reference from built-in catalog |
| `make docs-controls-check` | Verify reference is up to date |
| `make docs-commands` | CLI command reference from cobra tree |
| `make docs-commands-check` | Verify command reference matches binary |
| `make docs-commands-catalog` | Curated root `commands-catalog.md` |
| `make docs-commands-catalog-check` | Verify catalog matches annotations |
| `make docs-datalog` | Datalog relations reference from `.dl` source |
| `make docs-datalog-check` | Verify Datalog reference is up to date |
| `make docs-site` | Docusaurus CLI reference pages |
| `make docs-site-check` | Verify site CLI reference |
| `make docs-coverage` | Methodology coverage docs |
| `make docs-coverage-check` | Verify methodology coverage is up to date |
| `make metrics` | Generate `docs/metrics.yaml` from live codebase counts |
| `make sync-guide` | Refresh `projects/stave-guide/` from generated docs |

### Consistency & Drift

| Target | What It Does |
|--------|-------------|
| `make consistency-check` | Verify ALL derived artifacts match canonical sources |
| `make stale-terminology-check` | Reject stale `internal/domain` references |
| `make check-unsafe-writes` | Forbid unsafe file writes in cmd/app |
| `make attack-stage-check` | Reject invalid `attack_stage` values |
| `make domain-check` | Soft-enum check on `domain:` values |
| `make clig-check` | Verify CLI follows clig.dev guidelines |
| `make determinism` | Verify `apply --profile` output is deterministic |

### Encoding Verification

| Target | What It Does |
|--------|-------------|
| `make verify-encoding-demos` | Verify SIR encoding for demo scenarios |
| `make verify-encoding-controls` | Verify SIR encoding for control testdata |
| `make verify-encoding-e2e` | Verify SIR encoding for e2e fixtures |
| `make demo-check` | Demo scenarios finding counts + encoding |

### Control & Discovery Tools

| Target | What It Does |
|--------|-------------|
| `make gencontrol ID=... NAME=... FIELD=... REMEDIATION=...` | Scaffold a new control YAML + fixtures |
| `make triage ARGS="--service acm"` | Triage AWS feature for control coverage gaps |
| `make quarterly-audit` | Run all gap discovery engines |
| `make quarterly-save` | Run quarterly audit and save as baseline |
| `make compliance-diff` | Diff framework checklist against catalog |
| `make semantic-diff` | Z3 symbolic differential on controls |
| `make chain-discover ARGS="..."` | Datalog reachability + Z3 chain discovery |

### Sync & Release

| Target | What It Does |
|--------|-------------|
| `make sync-schemas` | Copy `schemas/` → `internal/contracts/schema/embedded` (hash-gated) |
| `make sync-controls` | Copy `controls/` → `internal/controldata/embedded` (hash-gated) |
| `make sync-alternatives` | Copy `data/alternatives/` → embedded (hash-gated) |
| `make sync` | Sync to public repo (`~/work/stave/`) |
| `make sync-skills` | Sync Superpowers skills to public repo |
| `make release V=0.0.3` | Prepare and tag a release |
| `make release-local` | Local snapshot release (GoReleaser) |
| `make release-check` | Validate GoReleaser config |
| `make reproduce-release` | Reproduce release binaries for checksum comparison |

### Misc

| Target | What It Does |
|--------|-------------|
| `make check` | All checks (fmt, vet, lint, terminology, deadcode, test) |
| `make ci` | CI pipeline (tidy, check, build) |
| `make run` | Run with default fixtures |
| `make run-now` | Run with fixed time for deterministic output |
| `make parallelize PKG=...` | Insert `t.Parallel()` into tests |
| `make gen-steampipe-mappings` | Generate Steampipe→Stave mapping YAMLs |
| `make gen-steampipe-mappings-validate` | Validate mapping accuracy |
| `make all` | lint + test + build |
| `make docker-demo` | Build demo Docker image |
| `make cover-report` | HTML coverage report from compliance tests |
| `make clean-cover` | Remove coverage files |
| `make refactor-scan-update` | Rewrite modernization baseline to current counts |
| `make help` | Show all targets |

---

## Developer Workflows

### Before committing Go changes

```bash
make gofixer      # modernization + deadcode + lint + test
make lint         # golangci-lint (gofixer does NOT run wrapcheck)
make consistency-check  # if controls or schemas changed
```

### Adding a new control

```bash
# 1. Scaffold
make gencontrol ID=CTL.S3.NEW.001 NAME="Control Name" \
  FIELD=properties.storage.access.public_read REMEDIATION="Fix text"

# 2. Edit the YAML, create fail.json/pass.json fixtures

# 3. Sync + test
make sync-controls
make test-pkg PKG=./internal/...  # or make test-fast

# 4. Regenerate goldens
make regenerate-goldens

# 5. Update metrics
make metrics

# 6. Update docs
make docs-controls
make consistency-check
```

### After modifying control YAML

```bash
make regenerate-goldens   # writes updated goldens, categorized diff
# Read the report: CLEAN/FINGERPRINT-ONLY/METADATA-ONLY = safe
# BEHAVIORAL/MIXED = investigate before committing
```

### Reproducing a CI shard failure

```bash
make test-shard SHARD=0   # enginetest (heaviest, ~383s)
make test-shard SHARD=1   # cmd/stave + graph + cel (~351s)
make test-shard SHARD=2   # controls/builtin + pack + pkg/stave (~255s)
make test-shard SHARD=3   # everything else (~150 packages)
```

---

## Project Layout

```
controls/               Canonical control YAML files (86 domains, 2908 controls)
chains/                 Compound chain YAML definitions (622 chains)
schemas/                JSON schemas (obs, ctrl, output, diagnose, finding)
data/
  frameworks/           Compliance framework YAMLs (8 frameworks)
  alternatives/         Alternative tool inventories
contracts/
  steampipe/            Steampipe→Stave mapping YAMLs
testdata/e2e/           E2E test fixtures (2687 fixtures)
examples/               Reference implementations and demos
experiments/            Experimental scripts
integrations/           Third-party integration configs (GitHub Actions, Atlantis, etc.)
features/               Feature scope definitions
reasoning/              Formal reasoning engines (Datalog)
reasoning-specs/        Reasoning specifications
fuzz/                   Fuzz grammars
scripts/                Shell/Python helper scripts
build/                  Build configuration (versions.md)
_skills/                Public early-adopter onboarding skills
.github/workflows/      CI workflows (ci, codeql, fuzz, release, coverage, docs-drift)
.stave-backlog/         Task system (TASKS.yaml, per-task prompts, articles)
docs/                   Internal docs (metrics.yaml, audits/, architecture/)
```

---

## Testing Patterns

### Golden file tests

Two mechanisms:

1. **In-process goldens**: test writes output, compares to
   `testdata/<fixture>.golden`. Regenerate with `UPDATE_GOLDEN=1`.
2. **E2E fixture goldens**: `regengoldens` tool runs the stave binary
   per fixture. Files: `expected.out.json`, `expected.summary.json`,
   `expected.findings.count`, `expected.exit`, `golden.json`.

### E2E fixture structure

```
testdata/e2e/<name>/
  controls/           Control YAML files (optional — uses builtins if absent)
  observations/       Observation JSON snapshots (minimum 2 for duration controls)
  expected.out.json   Golden output
  expected.summary.json
  expected.findings.count
  expected.exit       Expected exit code
```

### Determinism

Always use `--eval-time` for deterministic
output in tests. Time-dependent tests must pin the clock:

```go
cfg.Now = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
```

### Testscript

`cmd/stave/` uses `testscript` for behavioral CLI tests.
Run with `make script-test`.

---

## Control YAML

### File path

```
controls/<domain>/<subdomain>/CTL.<DOMAIN>.<SUBDOMAIN>.<TOPIC>.<SEQ>.yaml
```

Example: `controls/iam/semantics/CTL.IAM.SEMANTICS.FORALLVALUES.001.yaml`

### Minimal schema

```yaml
dsl_version: "1.0"
id: CTL.S3.ACCESS.PUBLIC.001
name: "Human-readable name"
description: >
  What the control checks and why it matters.
domain: storage
severity: critical | high | medium | low
compliance: {}
scope_tags: []
params: {}
remediation:
  description: "What's wrong"
  action: "How to fix it"
unsafe_predicate:
  # CEL predicate (any/all + field ops)
```

### Gencontrol flags

```bash
make gencontrol \
  ID=CTL.S3.NEW.001 \
  NAME="Control Name" \
  FIELD=properties.storage.access.public_read \
  REMEDIATION="Fix action text" \
  DOMAIN=storage \
  SEVERITY=high \
  SCOPE_TAGS="s3,access" \
  ASSET_TYPE=aws_s3_bucket \
  OP=eq \
  VALUE=true \
  COMPLIANCE="cis-aws-v3:2.1.1" \
  OUT=controls/s3/access/
```

---

## Recurring Tasks

Gap discovery engines run on a quarterly cadence. Each engine
has a make target and discovers controls the catalog is missing.

| Engine | Make Target | What It Discovers |
|--------|-------------|-------------------|
| AWS feature triage | `make triage ARGS="--service X"` | Controls needed for a new/changed AWS service |
| Compliance diff | `make compliance-diff` | Framework requirements not mapped to controls |
| Quarterly audit | `make quarterly-audit` | Consolidated gap report across all engines |
| Semantic diff | `make semantic-diff` | Predicate equivalence regressions |
| Chain discovery | `make chain-discover` | Attack chains not covered by existing chain YAMLs |

```bash
# Run all engines and save as this quarter's baseline
make quarterly-save

# Triage a single service
make triage ARGS="--service lambda"

# Diff a framework
make compliance-diff ARGS="--framework cis-aws-v3"
```

---

## Task System

Task prompts live in `.stave-backlog/`. The directory contains
per-task prompt files used by Claude Code sessions.

```
.stave-backlog/
  audit/              Audit reports and baselines
```

Task prompts are standalone markdown files with metadata (id,
workstream, title, priority, status, depends_on) and phased
instructions. A new task is a new `.md` file in the appropriate
subdirectory.

---

## Formal Verification

### Engines

| Engine | Role | Location |
|--------|------|----------|
| Soufflé/Datalog | Path discovery (transitive closure) | `reasoning/souffle/` |
| Z3 | Semantic verification (condition satisfiability) | `internal/tools/semantic-diff/` |

### SIR export

```bash
stave export-sir --format jsonl --output facts.jsonl
```

### Datalog

```
reasoning/souffle/iam/schema.dl      Input relations
reasoning/souffle/iam/rules.dl       Effective access derivation
reasoning/souffle/iam/action_classes.dl  Action classifications
reasoning/souffle/discovery/discovery.dl  Chain discovery + classification
```

### Z3 proofs

```bash
make semantic-diff                         # all controls
make semantic-diff ARGS="-symbolic -v"     # verbose proof mode
```

---

## CI Workflows

| Workflow | File | Trigger |
|----------|------|---------|
| CI | `ci.yml` | push/PR to main, nightly | 
| CodeQL | `codeql.yml` | PR |
| Control Security Review | `control-security-review.yml` | Control YAML changes |
| Coverage | `coverage.yml` | PR |
| Docs Drift | `docs-drift.yml` | PR |
| Fuzz | `fuzz.yml` | Schedule |
| Release | `release.yml` | Tag push |

CI runs 4 test shards in parallel + consistency checks.
Go version is pinned in `go.mod` `toolchain` directive.

---

## Skills

Three skill trees, different formats:

### `skills/` (agentskills.io, private)

Auto-discovered by Claude Code. Project conventions, naming,
refactoring patterns. Excluded from public sync.

### `skills/superpowers/` (Superpowers format, private)

Four cloud-security pipeline skills:
- `verifying-cloud-security`
- `writing-stave-controls`
- `writing-steampipe-mappings`
- `writing-reasoning-specs`

### `_skills/` (public, ships with public repo)

Early-adopter onboarding sequence:
1. `_setup` — environment setup
2. `first-evaluation` — run first evaluation
3. `lab-validation` — validate with lab
4. `write-your-first-control` — author a control
5. `reasoning-engines` — formal verification
6. `snapshot-your-account` — capture live account

---

## Numbers

All counts come from `docs/metrics.yaml` (generated by `make metrics`).
Never hardcode counts in documentation.

```bash
make metrics
cat docs/metrics.yaml
```

---

## Commit Messages

```
feat(controls): add 7 deprecation lifecycle controls
feat(schema): add SageMaker Pipeline asset type
fix(semantic-diff): numeric comparison safe values
docs: update catalog count
refactor(taxonomy): move classifier to domain service
test: add boundary test for core/report
chore: bump golangci-lint to v2.11.3
```

Format: `<type>(<scope>): <description>`

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Security-audit gating failure (only `security-audit` command) |
| 2 | Invalid input or validation failure |
| 3 | Violations found (`apply`) or diagnostics found (`diagnose`) |
| 4 | Unexpected internal error |
| 130 | Interrupted (SIGINT/Ctrl+C) |

Exit 3 is success — it means the tool ran correctly and found violations.

---

## Key Files

| File | Purpose |
|------|---------|
| `VERSION` | Release version string |
| `go.mod` | Go version + toolchain pin |
| `build/mvp/versions.md` | All pinned dependency versions |
| `.golangci.yml` | Lint config + depguard architecture rules |
| `.golangci.audit.yml` | Advisory audit lint config |
| `docs/metrics.yaml` | Generated codebase counts |
| `docs/audits/lint-debt-baseline` | Wrapcheck debt ratchet floor |
| `docs/audits/refactor-scan-baseline` | Modernization ratchet floor |
| `CONTRIBUTING.md` | Contributor setup + workflow |
| `CLAUDE.md` | AI agent instructions (CLI rules, data formats, conventions) |
