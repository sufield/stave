# Stave

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sufield/stave/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sufield/stave)
[![Go Report Card](https://goreportcard.com/badge/github.com/sufield/stave)](https://goreportcard.com/report/github.com/sufield/stave)
[![codecov](https://codecov.io/gh/sufield/stave/branch/main/graph/badge.svg)](https://codecov.io/gh/sufield/stave)

A configuration safety evaluator that detects cloud resources remaining unsafe for too long, using only local config snapshots without using any cloud credentials.

Design philosophy: [docs/design-philosophy.md](docs/design-philosophy.md)
Quick onboarding: [docs/time-to-first-finding.md](docs/time-to-first-finding.md)

## Go Report Card

Stave is tracked on Go Report Card as module `github.com/sufield/stave`.

- Badge: `https://goreportcard.com/badge/github.com/sufield/stave`
- Report: `https://goreportcard.com/report/github.com/sufield/stave`

Go Report Card is run by their hosted service.
To refresh, visit the report URL above.

CI enforces equivalent local quality gates in `.github/workflows/go-quality.yml`:

- `go test ./...`
- `go vet ./...`
- `gofmt` check (fails on unformatted files)
- `staticcheck ./...`

Small differences can still happen because the hosted service may lag in indexing
or evaluate module discovery slightly differently.

## Problem

Infrastructure misconfigurations often go undetected until a breach occurs. Traditional security tools require cloud credentials and runtime access, creating additional attack surface. Stave solves this by:

- Analyzing configuration snapshots locally, without cloud API access
- Tracking how long resources remain in unsafe states over time
- Detecting repeated patterns of unsafe configurations (recurrence)
- Enforcing safety controls before deployment

## MVP Operating Assumption

For MVP, Stave assumes teams are capturing snapshots from **production**
environments to remediate **critical issues** quickly.

This assumption drives lifecycle behavior:

- Snapshot schedules prioritize near-term remediation (`stave snapshot upcoming`)
- Retention defaults favor current risk over long history (`stave snapshot prune`)
- Project config centralizes these defaults in `stave.yaml` so CI/CD behavior
  stays consistent across commands (`max_unsafe`, `snapshot_retention`,
  `capture_cadence`, `snapshot_filename_template`)

## Concepts

| Term | Definition |
|------|------------|
| **Snapshot** | A point-in-time observation of infrastructure resources, captured as JSON |
| **Resource** | A single infrastructure component (e.g., S3 bucket, IAM role) with properties |
| **Control** | A safety rule that resources must satisfy (defined in YAML) |
| **Unsafe Predicate** | Conditions that mark a resource as unsafe (e.g., `public: true`) |
| **Violation Event** | A detected violation with evidence and remediation guidance (serialized under the `findings` output field) |
| **Episode** | A contiguous period where a resource remained unsafe |
| **Max Unsafe Duration** | Maximum time a resource may remain unsafe before violation |
| **Recurrence** | Repeated unsafe episodes within a time window |

## Download

Pre-built signed binaries are available from [GitHub Releases](https://github.com/sufield/stave/releases).

Platform-native install paths (publish when ready):

```bash
# macOS (Homebrew tap)
brew tap sufield/tap
brew install stave
stave --version
```

```powershell
# Windows (winget)
winget install sufield.stave
stave --version
```

```powershell
# Windows (Chocolatey)
choco install stave -y
stave --version
```

**Supported platforms:**

| OS | Architecture | Artifact |
|----|-------------|----------|
| Linux | amd64 | `stave_<version>_linux_amd64.tar.gz` |
| Linux | arm64 | `stave_<version>_linux_arm64.tar.gz` |
| macOS | amd64 (Intel) | `stave_<version>_darwin_amd64.tar.gz` |
| macOS | arm64 (Apple Silicon) | `stave_<version>_darwin_arm64.tar.gz` |
| Windows | amd64 | `stave_<version>_windows_amd64.zip` |

Each release also includes `SHA256SUMS`, per-archive Cosign signature bundles
(`*.sigstore.json`), an SPDX SBOM, `provenance.json`, and GitHub build
provenance attestations.

```bash
# Download and extract (example: Linux amd64)
gh release download --repo sufield/stave --pattern "stave_*_linux_amd64.tar.gz"
tar xzf stave_*_linux_amd64.tar.gz
./stave --version
```

To verify release authenticity, see [Release Security](docs/trust/02-release-security.md).

## Build from Source

```bash
git clone https://github.com/sufield/stave.git
cd stave
make build
make install   # installs to $GOPATH/bin (no sudo required)
```

## Hello World

One command that proves the core loop:

Snapshot -> Evaluate -> Finding -> Evidence -> Fix hint -> Report artifact

```bash
stave demo
```

Expected output:

```
Found 1 violation: CTL.S3.PUBLIC.001
Asset: s3://demo-public-bucket
Evidence: BlockPublicAccess=false, ACL=public-read
Fix: enable account/bucket Block Public Access + deny public principals

Example (Terraform):

  resource "aws_s3_bucket_public_access_block" "example" {
    bucket                  = aws_s3_bucket.example.id
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
Report: ./stave-report.json
```

The report is saved to `./stave-report.json` in your current directory. View it:

```bash
cat stave-report.json            # full JSON report
jq . stave-report.json           # pretty-printed (requires jq)
```

### Compare safe vs unsafe

```bash
stave demo --fixture known-good  # zero violations (properly secured bucket)
stave demo --fixture known-bad   # one violation (default)
```

### Quickstart (your own data)

```bash
stave quickstart
```

`quickstart` auto-detects snapshots in the current directory and `./stave.snapshot/`, runs evaluation, and writes `./stave-report.json`. If no snapshots are found, it falls back to the built-in demo fixture.

```bash
# View results
cat stave-report.json

# Override report path or fix timestamp for CI
stave quickstart --report ./output/report.json --now 2026-01-15T00:00:00Z
```

Output shape:

```
Source: <detected-path-or-built-in-demo-fixture>
Top finding: CTL.S3.PUBLIC.001
Asset: s3://demo-public-bucket
Fix: enable account/bucket Block Public Access + deny public principals
Report: stave-report.json
Next: run `stave demo --fixture known-good` to compare safe output.
```

### What to do after your first finding

```bash
# 1) Check what Stave needs from you
stave status

# 2) Set up a project
stave init --profile mvp1-s3
cd my-project

# 3) Validate, then evaluate
stave validate
stave apply --format json > output/evaluation.json
```

See full fast-path and troubleshooting: `docs/time-to-first-finding.md`.

## CLI Commands

Stave provides these commands:

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `demo` | Hello world | Get first finding in 60 seconds — `cat stave-report.json` to view |
| `quickstart` | Fast-lane evaluation | Auto-detect snapshots and evaluate — `cat stave-report.json` to view |
| `status` | Project state | See where you are and what command to run next |
| `doctor` | Environment readiness | Check environment prerequisites and tool availability |
| `init` | Project scaffolding | Initialize a new Stave project with sane defaults |
| `validate` | Input correctness | Before evaluation, verify inputs are sound |
| `plan` | Readiness gate | Confirm prerequisites and input readiness |
| `apply` | Control engine execution | Detect violations, produce findings |
| `explain` | Control field requirements | Show what fields a control needs from observations |
| `lint` | Control quality checks | Validate control design quality rules |
| `diagnose` | Explanation | Understand unexpected results |
| `trace` | Predicate debugging | Step-by-step PASS/FAIL trace of a single control against a single resource |
| `snapshot ...` | Snapshot lifecycle | `snapshot upcoming|diff|prune|archive|quality|hygiene` |
| `ci ...` | CI policy + baseline + fix verification loop | `ci baseline ...`, `ci gate`, `ci fix-loop` |
| `config ...` | Project config management | `config show|get|set` for effective values and updates |
| `context ...` | Named project defaults | `context use|show` for default path/config sets by project context |
| `fmt` | Deterministic formatting | Canonicalize control YAML and observation JSON files |
| `generate ...` | Starter artifact generation | Generate control/observation templates (`generate control|observation`) |
| `controls ...` | Control management | `controls list\|explain\|aliases\|alias-explain` for control discovery |
| `packs ...` | Pack management | `packs list\|show` for control pack discovery |
| `docs ...` | Documentation workflow | `docs search` and `docs open` for terminal-first docs lookup |
| `ingest --profile mvp1-s3` | S3 observation generation | Convert AWS S3 snapshots to observations |
| `enforce` | Remediation artifacts | Generate remediation templates (PAB/SCP) from evaluation output |
| `fix` | Remediation guidance | Show remediation guidance for a specific finding |
| `verify` | Before/after comparison | Verify a fix resolved violations |
| `extractor new` | Extractor scaffolding | Scaffold a new custom extractor project |
| `report` | Evaluation report | Generate plain-text markdown report with TSV findings for unix pipes |
| `capabilities` | Feature discovery | Show supported versions, source types, and packs |
| `alias ...` | Command aliases | `alias set\|list\|delete` for user-defined command shortcuts |
| `bug-report` | Diagnostic bundle | Collect environment and config info for bug reports |
| `prompt from-finding` | LLM prompt generation | Generate LLM prompt from evaluation findings |
| `env list` | Environment variables | List supported STAVE_* environment variables |
| `schemas` | Schema discovery | List wire-format contract schemas |
| `version` | Version info | Print version info (also available as `--version` flag) |

### CLI Docs Source Of Truth

CLI reference docs are generated by the sibling `../publisher` workspace:

- run: `cd ../publisher && make docs-gen`
- output: `docs-content/cli-reference` (or `DOCS_CONTENT_DIR`)

Treat generated CLI reference pages as canonical for command usage and flags.

### Command Flow

```
validate → plan → apply → diagnose
   ↓          ↓          ↓
 Inputs    Findings   Insights
  OK?       Found?    Why?
                        ↓
                      trace
                        ↓
                   Clause-by-clause
                     PASS/FAIL
```

**Recommended workflow:**
1. Run `validate` first to catch input errors early
2. Run `plan` to confirm readiness and resolve blockers
3. Run `apply` to detect violations
4. If results are unexpected, run `diagnose` to understand why
5. For clause-level detail, run `trace` on a single control + resource

### Most Common Recipes

```bash
# 1) Validate first (always)
stave validate --controls ./controls --observations ./observations

# 2) Check readiness
stave plan --controls ./controls --observations ./observations

# 3) Execute control engine and capture machine-readable output
stave apply --controls ./controls --observations ./observations --format json > output/evaluation.json

# 4) Track upcoming snapshot actions (CI-friendly summary optional)
stave snapshot upcoming --controls ./controls --observations ./observations --summary-out "$GITHUB_STEP_SUMMARY"

# 3a) Inspect effective defaults and their sources
stave config show --format json
stave config explain --format json

# 3b) Manage project config from terminal
stave config get max_unsafe
stave config set max_unsafe 72h
stave config set snapshot_retention_tiers.non_critical 14d

# 3c) Set context defaults for this project
stave context use prod --controls ./controls --observations ./observations --config ./stave.yaml

# 5) Explain unexpected outcomes
stave diagnose --controls ./controls --observations ./observations --previous-output output/evaluation.json

# 5a) Trace a single control against a single resource for clause-level detail
stave trace --control CTL.S3.PUBLIC.001 --observation observations/2026-01-15T00:00:00Z.json --asset-id my-bucket

# 6) Continue where you left off
stave status

# 7) Search docs from terminal
stave docs search "snapshot upcoming"

# 8) Resolve a topic to one best doc page path + summary
stave docs open "snapshot upcoming"

# 9) Format and generate artifacts
stave fmt ./controls
stave generate control s3.public-read
stave generate observation s3.snapshot

```

Supported `stave config get/set` keys:
- `max_unsafe`
- `snapshot_retention`
- `default_retention_tier`
- `ci_failure_policy`
- `capture_cadence`
- `snapshot_filename_template`
- `snapshot_retention_tiers.<tier>`

### Snapshot Lifecycle Workflow

Use these commands to keep operational snapshot workflows predictable in CI/CD:

```bash
# Generate chronological action items (markdown + optional CI summary)
stave snapshot upcoming \
  --controls ./controls \
  --observations ./observations \
  --due-soon 24h \
  --status OVERDUE \
  --control-id CTL.S3.PUBLIC.001 \
  --format json \
  --out output/upcoming.md \
  --summary-out "$GITHUB_STEP_SUMMARY"

# Remove old snapshots using project retention defaults
stave snapshot prune --observations ./observations --dry-run
stave snapshot prune --observations ./observations --force
stave snapshot prune --observations ./observations --dry-run --format json

# Compare latest two snapshots for drift triage
stave snapshot diff --observations ./observations --format json --out output/diff.json

# Focus drift triage on specific change/resource slices
stave snapshot diff --observations ./observations --change-type modified --resource-type res:aws:s3:bucket --asset-id prod-

# Save and enforce a baseline (fail only on newly introduced findings)
stave ci baseline save --in output/evaluation.json --out output/baseline.json
stave ci baseline check --in output/evaluation.json --baseline output/baseline.json --fail-on-new

# Enforce project CI gate policy (any/new/overdue)
stave ci gate --in output/evaluation.json --baseline output/baseline.json

# Run remediation verification loop in one command
stave ci fix-loop --before ./obs-before --after ./obs-after --controls ./controls --out ./output

# Generate weekly lifecycle hygiene markdown report
stave snapshot hygiene --controls ./controls --observations ./observations --out output/weekly-hygiene.md

# Generate machine-readable hygiene stats for CI analytics
stave snapshot hygiene --controls ./controls --observations ./observations --format json --out output/weekly-hygiene.json

# Filter hygiene upcoming metrics by scope/status
stave snapshot hygiene --controls ./controls --observations ./observations --status OVERDUE --control-id CTL.S3.PUBLIC.001
```

Grouped commands are the canonical lifecycle/CI UX:

```bash
stave snapshot upcoming --controls ./controls --observations ./observations
stave snapshot diff --observations ./observations
stave snapshot prune --observations ./observations --dry-run
stave snapshot archive --observations ./observations --archive-dir ./observations/archive --dry-run
stave snapshot quality --observations ./observations --strict
stave snapshot hygiene --controls ./controls --observations ./observations --out output/weekly-hygiene.md
stave ci baseline save --in output/evaluation.json --out output/baseline.json
stave ci gate --in output/evaluation.json --baseline output/baseline.json
stave ci fix-loop --before ./obs-before --after ./obs-after --controls ./controls --out ./output
```

`stave.yaml` is the single project-level source of truth for lifecycle defaults:

```yaml
max_unsafe: 168h
snapshot_retention: 30d
default_retention_tier: critical
snapshot_retention_tiers:
  critical: 30d
  non_critical: 14d
ci_failure_policy: fail_on_any_violation
capture_cadence: daily
snapshot_filename_template: YYYY-MM-DDT00:00:00Z.json
```

Optional user-level CLI defaults can be set in `~/.config/stave/config.yaml`
(override path with `STAVE_USER_CONFIG`) to reduce repeated flags:

```yaml
cli_defaults:
  output: json
  quiet: false
  sanitize: false
  path_mode: base
  allow_unknown_input: false
```

`stave init` also scaffolds `cli.yaml` with commented keys
so teams can uncomment it per project shell.

Resolution precedence for defaults:
1. Explicit flags
2. Environment variables
3. Project config (`stave.yaml`)
4. User config (`~/.config/stave/config.yaml`)
5. Built-in defaults

Retention tier behavior:

- Use `snapshot prune --retention-tier critical|non_critical` to select retention policy.
- Use `snapshot archive --retention-tier critical|non_critical` for audit-preserving moves.
- If `--older-than` is explicitly provided, it overrides tier-based defaults.

`ci_failure_policy` modes:

- `fail_on_any_violation`: fail CI if current evaluation has any findings.
- `fail_on_new_violation`: fail CI only on findings newly introduced relative to baseline.
- `fail_on_overdue_upcoming`: fail CI when any upcoming action item is already overdue.

Cadence options from `stave init --capture-cadence`:

- `daily`: lower operational cost/noise, appropriate for most steady-state teams.
- `hourly`: tighter feedback loops for high-severity production remediation where drift can happen quickly.

This solves ad-hoc snapshot timing and naming drift, which otherwise weakens duration analysis and makes CI automation inconsistent.

### Restart And Resume

Use these commands when you return to a workflow later:

```bash
# Show current workflow state and artifacts
stave status

# Print the next recommended command to continue
stave status
```

Deterministic rerun pattern:

```bash
stave validate --controls ./controls --observations ./observations
stave apply --controls ./controls --observations ./observations --format json > output/evaluation.json
stave diagnose --controls ./controls --observations ./observations --previous-output output/evaluation.json
```

### Troubleshooting Quick Links

- Input/schema issues: `stave validate --fix-hints ...`
- Unexpected findings: `stave diagnose ...`
- Clause-level predicate debugging: `stave trace --control <id> --observation <file> --asset-id <id>`
- CLI reference: `docs/user-docs.md`
- Trust and I/O guarantees: `docs/trust/data-flow-and-io.md`
- Contributing: `CONTRIBUTING.md`
- Security reporting: `SECURITY.md`

## Feedback And Support

- Bug reports and feature requests: open a GitHub issue in this repository.
- Missing an intent in docs ("I want to ..."): open
  `https://github.com/sufield/stave/issues/new?template=docs_feedback.yml&title=docs%3A%20missing%20intent%20-%20`
- Security vulnerabilities: follow `SECURITY.md` for responsible disclosure.
- Contributions: see `CONTRIBUTING.md` for development workflow and PR expectations.

## S3 Assessment Workflow

The MVP golden path for S3 public exposure assessment:

```
ingest --profile mvp1-s3 → evaluate --profile mvp1-s3 → verify
```

```bash
# 1. Extract observations from offline AWS snapshot
stave ingest --profile mvp1-s3 --input ./aws-snapshot --out observations.json --include-all

# 2. Evaluate against S3 controls (exit 3 = violations found)
stave apply --profile mvp1-s3 --input observations.json --include-all > evaluation.json

# 3. Compare before/after snapshots to verify remediation
stave verify --before ./obs-before --after ./obs-after --controls ./controls/s3 \
  --now 2026-01-15T00:00:00Z --out ./output
```

See [docs/s3-assessment.md](docs/s3-assessment.md) for the full guide.

## Quickstart

```bash
# Validate inputs before evaluation
stave validate --controls controls/s3 --observations examples/observations/

# Evaluate with sample observations (168h threshold)
stave apply --controls controls/s3 --observations examples/observations/

# Diagnose unexpected results
stave diagnose --controls controls/s3 --observations examples/observations/
```

For a detailed guide with a complete command map and recipes, see the full [User Documentation](docs/user-docs.md).

## Commands

### validate

Checks that inputs are well-formed and consistent as a pre-evaluation validation step.

```bash
stave validate [flags]
```

**Purpose:** Verify inputs are sound before evaluation (Stave's **intent evaluation** preflight stage).

**Artifact modes:**
- Directory mode validates both artifact sets together:
  `--controls` (YAML controls) + `--observations` (JSON observations)
- Single-file mode uses `--in` content detection:
  leading `{` or `[` => observation JSON; otherwise => control YAML

**What it checks:**
- Control schema and required fields (id, name, description)
- Observation schema and timestamps
- Cross-file consistency (predicates reference valid properties)
- Time sanity (snapshots sorted, unique timestamps, --now valid)
- Duration feasibility (snapshot span vs max-unsafe)

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All inputs valid |
| 2 | Validation errors or warnings found |

**Example:**
```bash
stave validate --controls controls/s3 --observations observations/ --format json

# Single-file validation with auto-detection
stave validate --in observations/2026-01-01T00:00:00Z.json
stave validate --in controls/s3/public/CTL.S3.PUBLIC.001.yaml
```

### apply

Evaluates configuration snapshots against safety controls to detect violations.

```bash
stave apply [flags]
```

**Purpose:** Produce findings by enforcing controls.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--controls` | `controls/s3` | Path to control definitions |
| `--observations` | `observations` | Path to observation snapshots |
| `--max-unsafe` | `168h` | Maximum allowed unsafe duration |
| `--now` | (current time) | Override evaluation time (RFC3339) |
| `--integrity-manifest` | (none) | Verify loaded observation files against expected SHA-256 hashes in a manifest JSON |
| `--integrity-public-key` | (none) | Verify signed manifest with Ed25519 public key (requires `--integrity-manifest`) |
| `--context` | (none) | Path to evaluation context YAML |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | No violations found |
| 2 | Input/validation error |
| 3 | Violations detected |

**Example:**
```bash
stave apply --controls controls/s3 --observations observations/ --max-unsafe 7d

# Integrity-checked evaluation (unsigned manifest)
stave apply \
  --controls controls/s3 \
  --observations observations/ \
  --integrity-manifest observations.manifest.json

# Integrity-checked evaluation (signed manifest)
stave apply \
  --controls controls/s3 \
  --observations observations/ \
  --integrity-manifest observations.signed-manifest.json \
  --integrity-public-key observations.pub
```

**Manifest format:**
```json
{
  "files": {
    "2026-01-01T00:00:00Z.json": "<sha256-hex>"
  },
  "overall": "<sha256-hex>"
}
```
If integrity verification fails (missing file, extra file, hash mismatch, or invalid signature), `stave apply` exits with an input/validation error.

### diagnose

Analyzes inputs and results to explain unexpected outcomes.

```bash
stave diagnose [flags]
```

**Purpose:** Understand why evaluation produced (or didn't produce) certain findings.

**What it explains:**
- Expected violations but got none (threshold too high, time span too short)
- Unexpected violations (clock skew, streak reset)
- Empty findings (no predicate matches, under threshold)

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | No diagnostic issues |
| 2 | Input/validation error |
| 3 | Diagnostic issues found |

**Example:**
```bash
stave diagnose --controls controls/s3 --observations observations/ --format json

# Focus on specific diagnostic case types
stave diagnose --controls controls/s3 --observations observations/ --case expected_violations_none
```

### ingest --profile mvp1-s3

Extracts S3 bucket observations from an offline AWS CLI snapshot directory. No AWS API calls — fully offline. Deterministic when `--now` is set.

```bash
stave ingest --profile mvp1-s3 --input ./aws-snapshot --out observations.json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | (required) | Path to AWS snapshot directory |
| `--out` | `observations.json` | Path to output observations file |
| `--scope` | (none) | Path to health scope config YAML |
| `--bucket-allowlist` | (none) | Bucket names/ARNs to include |
| `--include-all` | `false` | Disable health scope filtering |
| `--now` | (current time) | Override current time (RFC3339) |

**Input directory structure:**
```
aws-snapshot/
├── list-buckets.json              (required)
├── get-bucket-tagging/<bucket>.json
├── get-bucket-policy/<bucket>.json
├── get-bucket-acl/<bucket>.json
└── get-public-access-block/<bucket>.json
```

**Examples:**
```bash
# Extract with default health scope (tag-based: DataDomain=health, containsPHI=true)
stave ingest --profile mvp1-s3 --input ./aws-snapshot --out observations.json

# Extract specific buckets
stave ingest --profile mvp1-s3 --input ./aws-snapshot --out obs.json --bucket-allowlist my-phi-bucket

# Extract all buckets (no filtering)
stave ingest --profile mvp1-s3 --input ./aws-snapshot --out obs.json --include-all
```

### apply --profile mvp1-s3

Evaluates S3 observations against the healthcare (PHI) control profile. Uses the built-in S3 controls from `controls/storage/object_storage/s3/`.

```bash
stave apply --profile mvp1-s3 --input observations.json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | (required) | Path to observations JSON file |
| `--bucket-allowlist` | (none) | Bucket names/ARNs to include |
| `--include-all` | `false` | Disable health scope filtering |
| `--format` | `json` | Output format: `json` or `text` |
| `--now` | (current time) | Override current time (RFC3339) |
| `--quiet` | `false` | Suppress output (exit code only) |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | No violations found |
| 2 | Input error |
| 3 | Violations detected |

**Examples:**
```bash
# Evaluate with default health scope
stave apply --profile mvp1-s3 --input observations.json

# Evaluate all buckets
stave apply --profile mvp1-s3 --input observations.json --include-all

# Deterministic evaluation
stave apply --profile mvp1-s3 --input observations.json --now 2026-01-15T00:00:00Z
```

### capabilities

Displays supported schema versions, source types, and control packs.

```bash
stave capabilities
```

## Configuration

### Observation Snapshots (JSON)

Place snapshot files in the observations directory. Each file represents a point-in-time capture of your infrastructure.

```json
{
  "schema_version": "obs.v0.1",
  "generated_by": {
    "source_type": "terraform.plan_json",
    "tool": "terraform",
    "tool_version": "1.6.3"
  },
  "captured_at": "2026-01-01T00:00:00Z",
  "resources": [
    {
      "id": "res:aws:s3:bucket:my-bucket",
      "type": "storage_bucket",
      "vendor": "aws",
      "properties": {
        "public": true,
        "data_classification": "PII"
      },
      "source": {
        "file": "infra/main.tf",
        "line": 42
      }
    }
  ]
}
```

The `generated_by` field is validated by default. Use `--allow-unknown-input` to skip source type validation.

### Supported Source Types

Stave validates the `generated_by.source_type` field against a built-in allowlist. **Supported** types have shipped controls and extractors. **Preview** types are accepted by the engine but have no shipped control packs. Use `--allow-unknown-input` for custom types not in this list.

| Source Type | Status | Description |
|-------------|--------|-------------|
| `terraform.plan_json` | Supported | Terraform plan JSON output (`terraform show -json`) |
| `kubernetes.manifest` | Preview | Kubernetes YAML manifest files |
| `kubernetes.rbac` | Preview | Kubernetes RBAC configuration files |
| `gitlab` | Preview | GitLab CI configuration files |
| `keycloak` | Preview | Keycloak realm export JSON files |
| `oidc` | Preview | Generic OIDC/SSO configuration files |
| `secrets` | Preview | Secret detection in configuration files |
| `jenkins` | Preview | Jenkins pipeline files |
| `wordpress` | Preview | WordPress installation files |
| `drupal` | Preview | Drupal installation files |
| `joomla` | Preview | Joomla installation files |
| `woocommerce` | Preview | WooCommerce installation files |
| `shopware` | Preview | Shopware 6 installation files |
| `saleor` | Preview | Saleor headless commerce installation files |

Run `stave capabilities` to see the current allowlist.

### Control Definitions (YAML)

Controls define safety rules. Stave includes a core pack and supports custom packs.

```yaml
dsl_version: ctrl.v1
id: CTL.EXP.DURATION.001
name: Unsafe Duration Bound
description: A resource must not remain unsafe beyond the configured time window.
type: unsafe_duration
unsafe_predicate:
  any:
    - field: "properties.public"
      op: "eq"
      value: true
```

#### Predicate Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals (string, bool, numeric) | `{op: "eq", value: true}` |
| `ne` | Not equals | `{op: "ne", value: "COMPLIANCE"}` |
| `gt` | Greater than (numeric) | `{op: "gt", value: 1}` |
| `lt` | Less than (numeric) | `{op: "lt", value: 2190}` |
| `gte` | Greater than or equal (numeric) | `{op: "gte", value: 365}` |
| `lte` | Less than or equal (numeric) | `{op: "lte", value: 90}` |
| `missing` | Field absent or empty | `{op: "missing", value: true}` |
| `present` | Field exists and non-empty | `{op: "present", value: true}` |
| `in` | Value in list | `{op: "in", value: ["PII", "PHI"]}` |
| `list_empty` | List field is empty or missing | `{op: "list_empty", value: true}` |
| `contains` | String contains substring | `{op: "contains", value: "admin"}` |
| `neq_field` | Value not equal to another field | `{op: "neq_field", value: "other_field"}` |
| `not_in_field` | Value not in list from another field | `{op: "not_in_field", value: "allowed_list"}` |
| `not_subset_of_field` | List has elements not in another field | `{op: "not_subset_of_field", value: "allowed_items"}` |
| `any_match` | Any array element matches nested predicate | See identity controls |

#### Predicate Logic

- `any`: OR logic (at least one must match)
- `all`: AND logic (all must match)

### Evaluation Context

The `--context` flag enables breach-type routing, filtering which controls are evaluated based on incident context.

```yaml
# context.yaml
breach_type: DISC
incident_id: INC-2026-001
```

**Usage:**
```bash
stave apply \
  --controls ./controls \
  --observations ./observations \
  --context context.yaml \
  --max-unsafe 168h
```

**Supported Breach Types:**

| Code | Breach Type | Status |
|------|-------------|--------|
| `DISC` | Disclosure (unintended data exposure) | ✅ Supported |
| `HACK` | Hacking (external attack) | Returns `NOT_APPLICABLE` |
| `INSD` | Insider threat | Returns `NOT_APPLICABLE` |
| `PHYS` | Physical breach | Returns `NOT_APPLICABLE` |
| `PORT` | Portable device loss | Returns `NOT_APPLICABLE` |
| `UNKN` | Unknown | Returns `NOT_APPLICABLE` |

**DISC Allowlist:**

When `breach_type: DISC` is specified, only these controls are evaluated:

| Control ID | Description |
|--------------|-------------|
| `CTL.TP.PLATFORM.001` | Third-Party Platform Boundaries |
| `CTL.TP.VENDOR.001` | Third-Party Vendor Data Boundaries |
| `CTL.PROC.MAIL.001` | Process Audience Verification |
| `CTL.ID.AUTHZ.001` | Least-Privilege Subject Access |

**Behavior:**
- Default behavior (`--context` not set): all controls are evaluated with full scope.
- With `--context` and `breach_type: DISC`: Only DISC-applicable controls run
- With `--context` and other breach types: Returns exit code 0 with `NOT_APPLICABLE` status

### Tuning Time Thresholds

Customers can tune the unsafe duration threshold at two levels:

#### 1. CLI Global Default

Use `--max-unsafe` to set the default threshold for all controls:

```bash
# 7-day threshold (default is 168h)
stave apply --controls ./controls --observations ./obs --max-unsafe 7d

# 72-hour threshold (stricter)
stave apply --controls ./controls --observations ./obs --max-unsafe 72h

# 30-day threshold (more lenient)
stave apply --controls ./controls --observations ./obs --max-unsafe 30d
```

**Supported duration formats:**
- Hours: `72h`, `168h`, `24h30m`
- Days: `7d`, `30d` (converted to hours internally)

#### 2. Per-Control Override

Set `params.max_unsafe_duration` in an control YAML to override the CLI default for that specific control:

```yaml
# controls/custom/strict-pii-exposure.yaml
dsl_version: ctrl.v1
id: CTL.CUSTOM.PII.001
name: PII Exposure Duration
description: PII resources must not remain public beyond 24 hours.
type: unsafe_duration
params:
  max_unsafe_duration: "24h"  # Overrides CLI --max-unsafe
unsafe_predicate:
  all:
    - field: "properties.public"
      op: "eq"
      value: true
    - field: "properties.data_classification"
      op: "eq"
      value: "PII"
```

**Precedence:**
1. Per-control `params.max_unsafe_duration` (highest priority)
2. CLI `--max-unsafe` flag (fallback default)
3. Built-in default: `168h` (7 days)

**Example: Mixed Thresholds**

```bash
# CLI sets 7-day default, but PII control uses 24h from YAML
stave apply \
  --controls ./controls \
  --observations ./obs \
  --max-unsafe 7d
```

In this example:
- Standard controls use the 7-day CLI threshold
- The PII control uses its own 24-hour threshold from YAML

### Control Packs

Stave organizes controls into packs. The `core/` pack provides foundational controls. The `paid/` directory contains additional control packs requiring a commercial license.

```
controls/
├── core/                    # Foundational controls (included)
│   ├── CTL.EXP.DURATION.001-unsafe-duration.yaml
│   └── CTL.ID.AUTHZ.002-identity-blast-radius.yaml
└── paid/                    # License-gated packs (requires license)
    └── blind_harm/          # Blind Exposure & Silent Harm Pack
        ├── CTL.EXP.DURATION.001.yaml # Unsafe Exposure Duration Bound
        ├── CTL.EXP.RECURRENCE.001.yaml # Unsafe Exposure Recurrence Bound
        ├── CTL.EXP.JUSTIFICATION.001.yaml # Public Access Requires Business Justification
        ├── CTL.EXP.STATE.001.yaml # Sensitive Data Must Not Be Public
        ├── CTL.EXP.OWNERSHIP.001.yaml # Public Exposure Requires Owner
        ├── CTL.ID.AUTHZ.001.yaml # Least-Privilege Subject Access
        ├── CTL.META.VISIBILITY.001.yaml # Unknown Exposure Is Unsafe
        ├── CTL.PROC.MAIL.001.yaml # Process Audience Verification
        ├── CTL.TP.PLATFORM.001.yaml # Third-Party Platform Boundaries
        └── CTL.TP.VENDOR.001.yaml # Third-Party Vendor Data Boundaries
```

## Output Format

Stave outputs JSON with findings:

```json
{
  "run": {
    "now": "2026-01-11T00:00:00Z",
    "max_unsafe": "168h0m0s",
    "snapshots": 3
  },
  "summary": {
    "resources_evaluated": 2,
    "attack_surface": 1,
    "violations": 1
  },
  "findings": [
    {
      "control_id": "CTL.EXP.DURATION.001",
      "control_name": "Unsafe Duration Bound",
      "asset_id": "res:aws:s3:bucket:public-bucket",
      "asset_type": "storage_bucket",
      "asset_vendor": "aws",
      "source": {"file": "infra/main.tf", "line": 42},
      "evidence": {
        "first_unsafe_at": "2026-01-01T00:00:00Z",
        "last_seen_unsafe_at": "2026-01-11T00:00:00Z",
        "unsafe_duration_hours": 240,
        "threshold_hours": 168
      },
      "remediation": {
        "description": "Resource has been unsafe beyond the allowed duration threshold.",
        "action": "Review and remediate the unsafe configuration."
      }
    }
  ]
}
```

### Recurrence Findings

For recurrence violations, evidence includes episode information:

```json
{
  "evidence": {
    "episode_count": 3,
    "window_days": 30,
    "recurrence_limit": 3,
    "first_episode_at": "2026-01-01T00:00:00Z",
    "last_episode_at": "2026-01-25T00:00:00Z"
  }
}
```

## Scripting and CI

Stave follows Unix CLI conventions for scripting and automation.

### Exit Codes

| Code | evaluate | validate | diagnose |
|------|----------|----------|----------|
| 0 | No violations | All inputs valid | No diagnostics |
| 2 | Input error | Errors or warnings | Input error |
| 3 | Violations found | N/A | Diagnostics found |
| 4 | Internal error | Internal error | Internal error |
| 130 | Interrupted (SIGINT) | Interrupted | Interrupted |

### Exit Code Checking

Use exit codes for CI/CD integration:

```bash
# Simple pass/fail check
if stave apply --quiet --controls ./controls --observations ./obs; then
  echo "All resources are safe"
else
  echo "Violations found (exit code: $?)"
  exit 1
fi

# Detailed exit code handling
stave apply --controls ./controls --observations ./obs
case $? in
  0) echo "Clean - control checks passed" ;;
  2) echo "Input validation needs attention - check your files" ;;
  3) echo "Violations found - review findings" ;;
  *) echo "Unexpected result - review command output" ;;
esac
```

### Quiet Mode

Use `--quiet` to suppress output and rely only on exit codes:

```bash
# Validate inputs in quiet mode
stave validate --quiet --controls ./controls --observations ./obs && echo "Valid"

# Check for violations with terminal summary output
if stave apply --quiet --controls ./controls --observations ./obs; then
  echo "Safe"
fi

# Diagnose in quiet mode
stave diagnose --quiet --controls ./controls --observations ./obs
```

### Output Formats

All commands support `--format` for output control:

```bash
# Human-readable text output
stave apply --controls ./controls --observations ./obs --format text

# JSON output (default for evaluate)
stave apply --controls ./controls --observations ./obs --format json

# JSON output for validate/diagnose
stave validate --controls ./controls --observations ./obs --format json
stave diagnose --controls ./controls --observations ./obs --format json
```

### Parsing JSON Output

Use `jq` to extract specific information:

```bash
# Count violations
stave apply --controls ./controls --observations ./obs | jq '.summary.violations'

# Extract asset IDs with violations
stave apply --controls ./controls --observations ./obs | jq -r '.findings[].asset_id'

# Get control IDs that were violated
stave apply --controls ./controls --observations ./obs | jq -r '.findings[].control_id' | sort -u

# Check validation errors
stave validate --controls ./controls --observations ./obs --format json | jq '.errors'

# Conditional processing based on violation count
violations=$(stave apply --controls ./controls --observations ./obs | jq '.summary.violations')
if [ "$violations" -gt 0 ]; then
  echo "Found $violations violations"
fi
```

### Strict Validation in CI

Use `--strict` to treat warnings as errors:

```bash
# Fail CI on any warnings
stave validate --strict --controls ./controls --observations ./obs

# Combined with quiet mode
stave validate --strict --quiet --controls ./controls --observations ./obs && echo "Valid (all checks passed)"
```

### Deterministic Runs

Stave output is **deterministic when `--now` is set**. Without `--now`, the
evaluation timestamp falls back to the wall clock (only when there are zero
snapshots — with snapshots, `now` is derived from the last snapshot's
`captured_at`). For fully reproducible, byte-identical output, always pass
`--now`:

```bash
# Deterministic: fixed time → identical output across runs
stave apply \
  --controls ./controls \
  --observations ./obs \
  --now 2026-01-15T00:00:00Z

# Snapshot testing (byte-identical comparison)
stave apply --controls ./controls --observations ./obs --now 2026-01-15T00:00:00Z > output.json
diff output.json expected.json
```

**How `--now` interacts with snapshots:**
- The evaluator caps `now` to the last snapshot's `captured_at` timestamp
  (evaluation time is capped at the latest snapshot in your data)
- If `--now` is earlier than the last snapshot, the provided value is used as-is
- Extract commands (`ingest --profile mvp1-s3`) use `--now` for the `captured_at` field in output

See [docs/evaluation-semantics.md](docs/evaluation-semantics.md) for the full
determinism model.

### Piping and Redirection

Stave separates stdout (results) from stderr (errors):

```bash
# Pipe JSON to jq
stave apply --controls ./controls --observations ./obs | jq '.findings[]'

# Read observation from stdin (pipeline composition)
cat snapshot.json | stave apply --controls ./controls --observations -

# Combine with extractors in a pipeline
some-extractor | stave apply --controls ./controls --observations -

# Redirect errors to a file
stave apply --controls ./controls --observations ./obs 2>errors.log

# Discard errors
stave apply --controls ./controls --observations ./obs 2>/dev/null

# Save output and check errors separately
stave apply --controls ./controls --observations ./obs >results.json 2>errors.log
```

**Stdin Support:** Use `-` as the observations path to read a single snapshot from stdin. This enables pipeline composition with extraction tools.

### Verbose and Debug Output

Use `-v` flags for troubleshooting:

```bash
# Verbose mode (INFO level logs to stderr)
stave apply --controls ./controls --observations ./obs -v

# Debug mode (DEBUG level)
stave apply --controls ./controls --observations ./obs -vv

# Write logs to file
stave apply --controls ./controls --observations ./obs --log-file run.log

# JSON-formatted logs
stave apply --controls ./controls --observations ./obs --log-format json -v
```

## Development

### Prerequisites

- Go 1.26.1+
- golangci-lint v2.8.0 (for linting — `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.8.0`)

### Build and Test

```bash
make build          # Build binary
make test           # Run tests
make test-coverage  # Tests with coverage report
make lint           # Run golangci-lint (same config as CI)
make lint-fix       # Auto-format with gofmt
make check          # All checks (fmt, vet, lint, test)
make ci             # Full CI pipeline
```

### Linting

Linting runs in CI on every PR via `.github/workflows/golangci-lint.yml` using `golangci-lint-action` with `only-new-issues: true` — only new code is checked. The config is in `.golangci.yml` (v2 format).

Enabled linters: `errcheck`, `gosec`, `govet`, `ineffassign`, `staticcheck`, `unused`.

To run locally with the same config as CI:

```bash
golangci-lint run ./...
```

Optional pre-commit secret scanning (recommended):

```bash
pipx install pre-commit
pre-commit install
pre-commit run --all-files
```

### Project Structure

```
stave/
├── cmd/stave/           # CLI entry point
│   └── cmd/             # Cobra commands
├── internal/
│   ├── domain/          # Core business logic (evaluator, predicates)
│   ├── app/             # Use case orchestration
│   └── adapters/        # Input/output adapters
│       ├── input/       # YAML/JSON loaders
│       └── out/         # JSON writer
└── controls/          # Control definition packs
```

## Supply-Chain Security

Stave uses [OpenSSF Scorecard](https://securityscorecards.dev/) to continuously assess repository security practices. Scorecard runs weekly and on every push to `main`, checking for branch protection, dependency management, CI practices, and more.

Results are published to:
- **GitHub Code Scanning** — findings appear in the Security tab under Code scanning alerts
- **OpenSSF API** — public results available via the badge above

Additional supply-chain protections:
- **Signed releases** — SHA256 checksums signed with Sigstore cosign
- **Build provenance** — GitHub-native SLSA attestation on release archives
- **SBOM** — SPDX Software Bill of Materials attached to every release
- **Dependency monitoring** — Dependabot for Go modules and GitHub Actions
- **Vulnerability scanning** — govulncheck runs on every PR

See [SECURITY.md](SECURITY.md) for vulnerability reporting, [docs/trust/02-release-security.md](docs/trust/02-release-security.md) for release verification, and [docs/offline-airgapped.md](docs/offline-airgapped.md) for air-gapped deployment guidance.

## Algorithm

The following applies to `unsafe_duration` and `unsafe_recurrence` control types:

1. Load snapshots from `--observations` directory, sorted by `captured_at`
2. For each control, build per-resource timelines tracking unsafe periods
3. When a resource transitions safe-to-unsafe, start an episode
4. When a resource transitions unsafe-to-safe, close the episode
5. For `unsafe_duration` controls: emit finding if `unsafe_duration > max_unsafe`
6. For `unsafe_recurrence` controls: emit finding if `episode_count >= recurrence_limit` within window

### Unsafe Streak Reset

When a resource becomes safe and later becomes unsafe again, the duration window resets:

```
Unsafe (Jan 1) → Safe (Jan 5) → Unsafe (Jan 10)
                                ↑ new episode starts
```

## S3 Controls (MVP 1.0)

Stave ships 40 S3 controls in `controls/s3/`. The MVP focus is public exposure and access control. Additional safety checks cover encryption, versioning, lifecycle, and governance.

### MVP Focus: Public Exposure & Access Control

These controls detect publicly exposed buckets, ACL privilege escalation, access policy violations, network scoping gaps, and governance controls.

| ID | Name | What It Detects |
|----|------|-----------------|
| `CTL.S3.PUBLIC.001` | No Public S3 Buckets | Any bucket with public read or list access |
| `CTL.S3.PUBLIC.002` | No Public S3 Buckets With Sensitive Data | Public access on PHI/PII/confidential buckets |
| `CTL.S3.PUBLIC.003` | No Public Write Access | Public write grants on any bucket |
| `CTL.S3.PUBLIC.004` | No Public Read via ACL | Public read via ACL grants |
| `CTL.S3.PUBLIC.005` | No Latent Public Read Exposure | Public read masked only by PAB (one change from exposed) |
| `CTL.S3.PUBLIC.006` | No Latent Public Bucket Listing | Public listing masked only by PAB |
| `CTL.S3.PUBLIC.LIST.002` | Anonymous S3 Listing Must Be Explicitly Intended | Public listing without `public_list_intended` tag |
| `CTL.S3.ACL.ESCALATION.001` | No Public ACL Modification | WRITE_ACP grants allowing public or authenticated users to modify the bucket ACL |
| `CTL.S3.ACL.RECON.001` | No Public ACL Readability | READ_ACP grants allowing public users to enumerate ACL grants |
| `CTL.S3.ACL.FULLCONTROL.001` | No FULL_CONTROL ACL Grants to Public | Explicit FULL_CONTROL grants to AllUsers or AuthenticatedUsers |
| `CTL.S3.ACCESS.001` | No Unauthorized Cross-Account Access | External account access to buckets |
| `CTL.S3.ACCESS.002` | No Wildcard Action Policies | Bucket policies with wildcard actions |
| `CTL.S3.ACCESS.003` | No External Write Access | External account write/delete access |
| `CTL.S3.AUTH.WRITE.001` | No Authenticated-Users Write Access | Write/delete access granted to all authenticated AWS users |
| `CTL.S3.NETWORK.001` | Public-Principal Policies Must Have Network Conditions | Public-principal policies without IP/VPC conditions |
| `CTL.S3.CONTROLS.001` | Public Access Block Must Be Enabled | Buckets without PAB fully enabled |
| `CTL.S3.GOVERNANCE.001` | Data Classification Tag Required | Buckets missing `data-classification` tag |
| `CTL.S3.WRITE.SCOPE.001` | S3 Signed Upload Must Bind To Exact Object Key | Upload policies using prefix-wide write instead of exact key |
| `CTL.S3.WRITE.CONTENT.001` | S3 Signed Upload Must Restrict Content Types | Upload policies without content-type restrictions (XSS risk) |
| `CTL.S3.TENANT.ISOLATION.001` | Shared-Bucket Tenant Isolation Must Enforce Prefix | Presigned URL signers without prefix enforcement on shared buckets |
| `CTL.S3.INCOMPLETE.001` | Complete Data Required for Safety Assessment | Missing inputs prevent safety proof |

### Additional Safety Checks

These controls enforce encryption, versioning, lifecycle, object lock, and logging requirements — particularly relevant for HIPAA/PHI compliance.

| ID | Name | What It Detects |
|----|------|-----------------|
| `CTL.S3.ENCRYPT.001` | Encryption at Rest Required | Buckets without server-side encryption |
| `CTL.S3.ENCRYPT.002` | Transport Encryption Required | Buckets without in-transit encryption enforcement |
| `CTL.S3.ENCRYPT.003` | PHI Buckets Must Use SSE-KMS with CMK | PHI buckets using AES256 instead of customer-managed KMS key |
| `CTL.S3.ENCRYPT.004` | Sensitive Data Requires KMS Encryption | Non-public classified data without SSE-KMS |
| `CTL.S3.VERSION.001` | Versioning Required | Buckets without versioning enabled |
| `CTL.S3.VERSION.002` | Backup Buckets Must Have MFA Delete | Backup-tagged buckets without MFA delete protection |
| `CTL.S3.LOG.001` | Access Logging Required | Buckets without access logging enabled |
| `CTL.S3.LIFECYCLE.001` | Retention-Tagged Buckets Must Have Lifecycle Rules | Retention-tagged buckets without lifecycle rules |
| `CTL.S3.LIFECYCLE.002` | PHI Buckets Must Not Expire Before Minimum Retention | PHI data expiring before 2190-day (6-year) HIPAA minimum |
| `CTL.S3.LOCK.001` | Compliance-Tagged Buckets Must Have Object Lock | Compliance-tagged buckets without WORM protection |
| `CTL.S3.LOCK.002` | PHI Buckets Must Use COMPLIANCE Mode | PHI buckets using GOVERNANCE mode (overridable) instead of COMPLIANCE |
| `CTL.S3.LOCK.003` | PHI Object Lock Retention Must Meet Minimum Period | PHI WORM retention below 2190-day (6-year) HIPAA minimum |

### Using S3 Controls

**With Terraform plan JSON (most common):**

```bash
# Point evaluate at your observations and the S3 control directory
stave apply \
  --controls controls/s3 \
  --observations ./observations \
  --max-unsafe 168h
```

**With the healthcare profile (pre-extracted AWS snapshots):**

```bash
# Step 1: Extract from AWS CLI snapshots
stave ingest --profile mvp1-s3 --input ./aws-snapshot --out observations.json

# Step 2: Evaluate against PHI controls
stave apply --profile mvp1-s3 --input observations.json
```

## S3 Terraform Plan Extraction

The `ingest --profile mvp1-s3` command converts AWS S3 snapshots into Stave observations. The S3 extractor handles these Terraform resource types:

| Terraform Resource Type | Fields Extracted |
|------------------------|-----------------|
| `aws_s3_bucket` | Bucket name, ARN, tags, `object_lock_enabled` |
| `aws_s3_bucket_policy` | Policy statements, public principal detection, network conditions |
| `aws_s3_bucket_acl` | ACL grants, public grantees |
| `aws_s3_bucket_public_access_block` | All four public access block settings |
| `aws_s3_bucket_server_side_encryption_configuration` | SSE algorithm, KMS key ID |
| `aws_s3_bucket_versioning` | Versioning status, MFA delete |
| `aws_s3_bucket_logging` | Target bucket, target prefix |
| `aws_s3_bucket_lifecycle_configuration` | Rules, expiration days, transitions |
| `aws_s3_bucket_object_lock_configuration` | Lock mode, retention period |
| `aws_s3_account_public_access_block` | Account-level public access overrides |

### S3 Canonical Storage Model

The extractor produces vendor-agnostic canonical fields under `properties.storage.*`:

```
properties.storage.
├── kind                                    # "bucket"
├── name                                    # Bucket name
├── tags                                    # Resource tags (map)
├── visibility.
│   ├── public_read                         # bool
│   ├── public_list                         # bool
│   ├── public_write                        # bool
│   ├── authenticated_users_read            # bool
│   ├── authenticated_users_write           # bool
│   ├── public_acl_writable                 # bool (WRITE_ACP to AllUsers)
│   ├── authenticated_users_acl_writable    # bool (WRITE_ACP to AuthenticatedUsers)
│   ├── public_acl_readable                 # bool (READ_ACP to AllUsers)
│   └── authenticated_users_acl_readable    # bool (READ_ACP to AuthenticatedUsers)
├── acl.
│   ├── has_full_control_public             # bool (FULL_CONTROL to AllUsers)
│   └── has_full_control_authenticated      # bool (FULL_CONTROL to AuthenticatedUsers)
├── controls.
│   ├── public_access_fully_blocked         # bool
│   └── account_public_access_fully_blocked # bool
├── encryption.
│   ├── at_rest_enabled                     # bool
│   ├── algorithm                           # "AES256" | "aws:kms"
│   ├── kms_key_id                          # KMS key ARN or ""
│   └── in_transit_enforced                 # bool
├── versioning.
│   ├── enabled                             # bool
│   └── mfa_delete_enabled                  # bool
├── logging.
│   ├── enabled                             # bool
│   ├── target_bucket                       # Target bucket name
│   └── target_prefix                       # Log prefix
├── access.
│   ├── external_accounts                   # List of external account IDs
│   ├── has_external_access                 # bool
│   └── has_wildcard_policy                 # bool
├── policy.
│   ├── has_ip_condition                    # bool
│   ├── has_vpc_condition                   # bool
│   └── effective_network_scope             # "public" | "ip-restricted" | "vpc-restricted"
├── lifecycle.
│   ├── rules_configured                    # bool
│   ├── rule_count                          # int
│   ├── has_expiration                      # bool
│   ├── has_transition                      # bool
│   ├── min_expiration_days                 # int (smallest enabled expiration)
│   └── has_noncurrent_version_expiration   # bool
└── object_lock.
    ├── enabled                             # bool
    ├── mode                                # "COMPLIANCE" | "GOVERNANCE" | ""
    └── retention_days                      # int (years × 365 if specified in years)
```

Controls reference these fields in their `unsafe_predicate`:

```yaml
# Example: PHI buckets must use KMS encryption
unsafe_predicate:
  all:
    - field: properties.storage.tags.data-classification
      op: eq
      value: "phi"
    - field: properties.storage.encryption.algorithm
      op: ne
      value: "aws:kms"
```

## Documentation

- [System Controls as Code](docs/system-controls-as-code.md) — What Stave proves, formal model, and alternatives positioning
- [Authoring Controls](docs/authoring-controls.md) — Create custom controls by editing YAML definitions, with no Stave core changes required
- [Observation Contract](docs/observation-contract.md) — Stable `obs.v0.1` contract and field dictionary
- [Contracts](docs/contracts.md) — Contract-first schemas for controls, observations, and findings
- `docs/schema/out.v0.1.md` — Evaluation output contract reference (`out.v0.1`)
- `docs/scope-and-support.md` — Scope, support status, and surface area reference
- `docs/user-docs.md` — Detailed command reference and usage guide
- `docs/sanitization.md` — Sharing outputs safely (sanitization and scrubbing)
- `docs/storage-canonical-model.md` — S3 canonical storage model specification
- `docs/e2e.md` — End-to-end test framework
- `docs/control-spec.md` — Control and observation schema specification

### System Controls as Code

Stave treats safety checks as controls over observed system state, alongside static lint rules, with snapshot-time context.
It focuses on deterministic, offline proofs from local snapshots.

How it differs from common alternatives:
- OPA/Sentinel: decision policy engines; Stave evaluates snapshot controls and time-window safety.
- tfsec/Checkov: IaC scanners; Stave evaluates normalized observed state snapshots.
- CSPM: credentialed continuous cloud monitoring; Stave is offline and local-file driven.

### Authoring controls

You can author new controls by editing YAML, without modifying the code for Stave.
Start with boundary-first rules, validate, evaluate, fix, and re-run:
- Guide: `docs/authoring-controls.md`

## Compatibility

### Schema Versions

| Schema | Version | Status |
|--------|---------|--------|
| Observations | `obs.v0.1` | Stable — no breaking changes within 1.x |
| Controls | `ctrl.v1` | Stable — no breaking changes within 1.x |

Schema versions are independent of the CLI version. See [controls/MIGRATION.md](controls/MIGRATION.md) for migration guidance.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

## Scope

In scope: AWS S3 public exposure (offline, deterministic).
Out of scope: CMS/e-commerce specifics, other AWS services, continuous monitoring.

### Quick test commands

- `make e2e-s3` — S3-only end-to-end tests
- `make e2e` — full end-to-end test suite
- `go test ./...` — unit and package tests
