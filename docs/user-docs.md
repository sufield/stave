# Stave User Documentation

Stave detects infrastructure assets that have remained unsafe for too long, using only configuration snapshots — no cloud credentials required.

## MVP Operating Assumption

For MVP, Stave assumes you are capturing snapshots from **production** environments to fix **critical issues**.

Design implications:

- `stave snapshot upcoming` is optimized for action-oriented, chronological next snapshots
- `stave snapshot prune` defaults to bounded retention so observation directories do not grow indefinitely
- `stave.yaml` centralizes lifecycle defaults (`max_unsafe`, `snapshot_retention`, `capture_cadence`, `snapshot_filename_template`) so command behavior stays consistent in local and CI/CD workflows

## Installation

### From Source

```bash
git clone https://github.com/sufield/stave.git
cd stave
make build
```

The binary will be created as `./stave`.

### Install to PATH

```bash
make install
```

This installs `stave` to your `$GOPATH/bin`.

## Quick Start

```bash
# Check capabilities
stave capabilities

# Validate inputs first
stave validate \
  --controls controls/s3 \
  --observations examples/observations/

# Run evaluation
stave apply \
  --controls controls/s3 \
  --observations examples/observations/ \
  --max-unsafe 168h

# Diagnose unexpected results
stave diagnose \
  --controls controls/s3 \
  --observations examples/observations/
```

## Path Inference

Stave can automatically find your `controls/` and `observations/` directories so you don't need to type `--controls` and `--observations` every time. This works with `apply`, `validate`, and `diagnose`.

### How It Works

When you omit `--controls` or `--observations`, Stave resolves in this order:

1. Check active context defaults (if set via `stave context use`)
2. Check the **project root** for `controls/` or `observations/` directly
3. If not found, search up to 3 levels deep for a uniquely named directory
4. If exactly one match is found, use it
5. If multiple or no matches are found, report an inference error with searched paths and fix flags

The project root is determined by:
- `STAVE_PROJECT_ROOT` environment variable (if set and valid)
- Otherwise, the current working directory

### Examples

```bash
# From a project root with conventional layout:
#   my-project/
#     controls/
#     observations/
cd my-project
stave apply                    # finds both dirs automatically
stave validate                    # same inference
stave diagnose                    # same inference

# Explicit flags always win:
stave apply --controls ./custom-controls   # no inference for controls

# Using STAVE_PROJECT_ROOT:
STAVE_PROJECT_ROOT=/path/to/project stave apply

# Set context defaults once for this project
stave context use prod --controls ./controls --observations ./observations --config ./stave.yaml

# If inference fails, Stave prints searched paths, candidates, and exact fix flags
```

### Constraints

- Explicit flags always take precedence over inference
- Only directories with the exact name are matched (no substring matching)
- Search depth is limited to 3 levels to keep inference fast and predictable
- Inference failures include what was missing, what was searched, candidates, and exact fix flags
- Inference is deterministic, offline, and non-interactive

## Intent Map

Use this table when you know your goal but want the fastest path to the right command and docs.

| I want to... | Run this command | Read this doc |
|--------------|------------------|---------------|
| Get my first finding in 60 seconds | `stave apply --observations examples/observations/ --max-unsafe 168h --now 2026-01-11T00:00:00Z` | [`time-to-first-finding.md`](time-to-first-finding.md) |
| Evaluate my own snapshots instantly | `stave init && stave validate && stave apply` | [`time-to-first-finding.md`](time-to-first-finding.md) |
| See where I am and what to do next | `stave status` | [`README.md`](../README.md) |
| Start a new project with sane defaults | `stave init --profile aws-s3` | [`README.md`](../README.md) |
| Validate controls and observations before evaluating | `stave validate --controls ./controls --observations ./observations` | [`README.md`](../README.md) |
| Evaluate current risk status | `stave apply --controls ./controls --observations ./observations --format json > output/evaluation.json` | [`README.md`](../README.md) |
| See what snapshot actions are due next | `stave snapshot upcoming --controls ./controls --observations ./observations --out output/upcoming.md` | [`README.md`](../README.md) |
| Inspect effective project defaults and override sources | `stave config show --format json` | [`README.md`](../README.md) |
| Query/update project config from terminal | `stave config get max_unsafe` / `stave config set max_unsafe 72h` | [`README.md`](../README.md) |
| Check if snapshots are stale/sparse before evaluation | `stave snapshot quality --observations ./observations --strict` | [`README.md`](../README.md) |
| Compare drift between latest snapshots | `stave snapshot diff --observations ./observations --format table` | [`README.md`](../README.md) |
| Keep observations folder bounded | `stave snapshot prune --observations ./observations --dry-run` | [`README.md`](../README.md) |
| Keep auditability while reducing active set | `stave snapshot archive --observations ./observations --archive-dir ./observations/archive --dry-run` | [`README.md`](../README.md) |
| Fail CI only for policy-relevant findings | `stave ci gate --in output/evaluation.json --baseline output/baseline.json` | [`README.md`](../README.md) |
| Run the full remediation verification loop | `stave ci fix-loop --before ./obs-before --after ./obs-after --controls ./controls --out output` | [`README.md`](../README.md) |
| Search docs without leaving terminal | `stave docs search "snapshot upcoming"` | [`README.md`](../README.md) |
| Open the best-matching docs page path + summary | `stave docs open "snapshot upcoming"` | [`README.md`](../README.md) |
| Resume from where you stopped | `stave status` then `stave status` | [`README.md`](../README.md) |
| Visualize which controls cover which assets | `stave graph coverage --controls ./controls --observations ./observations` | [`README.md`](../README.md) |
| Debug why a specific control matched or didn't match an asset | `stave trace --control CTL.S3.PUBLIC.001 --observation obs/snap.json --asset-id my-bucket` | [`README.md`](../README.md) |
| Generate a human-readable report from evaluation output | `stave report --in output/evaluation.json` | [`README.md`](../README.md) |
| Analyze a bucket policy directly | `stave inspect policy --file policy.json` | [Command Reference](command-reference.md) |
| Extract specific fields from evaluation output | `stave apply --template '{{.Summary.Violations}} violations'` | [`README.md`](../README.md) |
| Create a shortcut for a frequently used command | `stave alias set ev "apply --controls controls/s3 --observations observations --max-unsafe 24h"` | [`README.md`](../README.md) |

Need something not listed in this table?
- Suggest a missing intent or docs improvement:
  `https://github.com/sufield/stave/issues/new?template=docs_feedback.yml&title=docs%3A%20missing%20intent%20-%20`

### Most Common Command Recipes

```bash
# Validate first
stave validate --controls ./controls --observations ./observations

# Evaluate and save JSON output for downstream tooling
stave apply --controls ./controls --observations ./observations --format json > output/evaluation.json

# Diagnose unexpected outcomes from the same artifacts
stave diagnose --controls ./controls --observations ./observations --previous-output output/evaluation.json

# Trace a single control against a specific asset
stave trace --control CTL.S3.PUBLIC.001 --observation observations/2026-01-15T000000Z.json --asset-id my-bucket

# Continue from last successful workflow step
stave status
```

### Restart And Resume for Long Workflows

When you come back later, restart from the last stable artifact instead of redoing all steps.

```bash
# 1) See where to continue
stave status

# 2) Print the next recommended command
stave status
```

If you want explicit rerun patterns:

```bash
# Re-run validation from controls + normalized observations
stave validate --controls ./controls --observations ./observations

# Re-run evaluation and refresh output artifact
stave apply --controls ./controls --observations ./observations --format json > output/evaluation.json

# Re-run diagnose from existing evaluation output artifact
stave diagnose --controls ./controls --observations ./observations --previous-output output/evaluation.json
```

## Commands Overview

CLI usage docs are generated by sibling `../publisher` tooling via `make docs-gen`.
For command/flag-level reference, prefer generated CLI docs over ad-hoc hand-edited pages.

Stave provides these commands:

**Getting started** (run these first):

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `status` | Project state | See where you are and what command to run next |

**Core workflow:**

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `validate` | Input correctness | Before evaluation, verify inputs are sound |
| `apply` | Enforcement | Detect violations, produce findings |
| `diagnose` | Explanation | Understand unexpected results |
| `trace` | Predicate debugging | Step-by-step PASS/FAIL trace of a single control against a single asset |
| `inspect` | Domain analysis | Low-level policy, ACL, exposure, risk, and compliance analysis |
| `doctor` | Environment readiness | Check prerequisites before first run |
| `init` | Project scaffolding | Create project structure with `--profile`, `--dir`, `--capture-cadence` |
| `plan` | Readiness gate | Confirm prerequisites and input readiness before apply |
| `explain` | Control field requirements | Show what fields a control needs from observations |
| `fmt` | Deterministic formatting | Canonicalize control YAML and observation JSON |
| `lint` | Control quality | Validate control design quality rules |
| `verify` | Before/after comparison | Confirm a fix resolved violations |

For snapshot operations, use the lifecycle command set:

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `snapshot upcoming` | Chronological next actions | Generate due-now/due-soon/overdue items from current unsafe assets |
| `snapshot prune` | Retention enforcement | Remove stale snapshots so `observations/` remains bounded |
| `snapshot archive` | Audit-preserving retention | Move stale snapshots to archive directory instead of deleting |
| `snapshot diff` | Snapshot drift comparison | Focus remediation on what changed between latest two snapshots |
| `snapshot quality` | Snapshot quality gate | Warn/fail on sparse, stale, or missing-key-asset snapshots |
| `snapshot hygiene` | Weekly lifecycle report | Generate markdown with snapshot totals, retention posture, violations, upcoming items, and trend vs last week |
| `ci baseline save/check` | Fail-on-new CI policy | Preserve accepted findings and fail only on newly introduced findings |
| `ci gate` | CI policy enforcement | Apply configurable fail modes (`any`, `new`, `overdue`) |
| `ci fix-loop` | Fix verification loop | Apply before/after snapshots, verify changes, and generate remediation report |
| `config show` | Effective config inspection | Show resolved defaults and value sources (env/project/user/default) |
| `config explain` | Config resolution trace | Print effective values and where each value came from |
| `config get/set` | Config key management | Read or update `stave.yaml` keys from terminal and CI scripts |
| `context use/show` | Context defaults | Set/show named project defaults for controls/observations/config paths |
| `fmt` | Deterministic formatting | Canonicalize control YAML and observation JSON files |
| `generate` | Starter artifact generation | Create minimal control or observation templates quickly |
| `graph coverage` | Coverage visualization | Show which controls cover which assets (DOT or JSON output) |
| `report` | Evaluation report | Generate plain-text markdown report from evaluation output, with TSV findings for unix pipes |
| `alias ...` | Command aliases | `alias set|list|delete` for user-defined command shortcuts |
| `enforce` | Remediation artifacts | Generate PAB/SCP templates from evaluation output |
| `controls list\|explain\|aliases` | Control discovery | Browse, explain, and manage control aliases |
| — | Extractor development | Use an extractor (any language) to produce `obs.v0.1` JSON. See [Building an Extractor](extractor-prompt.md) |
| `packs list\|show` | Pack discovery | Browse available control packs |
| `fix` | Remediation guidance | Show fix guidance for a specific finding |
| `bug-report` | Diagnostic bundle | Collect environment info for bug reports |
| `prompt from-finding` | LLM prompt generation | Generate LLM prompt from findings |
| `env list` | Environment variables | List supported STAVE_* variables |
| `schemas` | Schema listing | List wire-format contract schemas |
| `version` | Version info | Print version (also `--version` flag) |

### Recommended Workflow

```
validate → plan → apply → diagnose
   ↓          ↓          ↓
 Inputs    Findings   Insights
  OK?       Found?    Why?
```

1. **validate** - Run first to catch input errors early (malformed YAML, missing fields, timestamp issues)
2. **apply** - Run to detect safety violations and produce findings
3. **diagnose** - Run when evaluation output differs from what you expected from your controls, snapshots, or prior runs
4. **trace** - Run for clause-level detail on why a specific control matched or didn't match a single asset

## Snapshot Lifecycle Workflow

### Centralized project config (`stave.yaml`)

Keep lifecycle defaults in one place per project:

```yaml
max_unsafe: 168h
snapshot_retention: 30d
default_retention_tier: critical
snapshot_retention_tiers:
  critical: 30d
  non_critical: 14d
ci_failure_policy: fail_on_any_violation
capture_cadence: daily
snapshot_filename_template: YYYY-MM-DDT000000Z.json
```

Optional user-level CLI defaults:

```yaml
# ~/.config/stave/config.yaml
cli_defaults:
  output: json
  quiet: false
  sanitize: false
  path_mode: base
  allow_unknown_input: false
```

`stave init` creates `cli.yaml` with commented keys you can uncomment.

This is useful for frequently used flags such as `--output`, `--quiet`, `--sanitize`,
`--path-mode`, and `--allow-unknown-input`.

Default resolution order:
1. Explicit flags
2. Environment variables
3. Project config (`stave.yaml`)
4. User config (`~/.config/stave/config.yaml`, or `STAVE_USER_CONFIG`)
5. Built-in defaults

- `max_unsafe` drives default thresholds for commands like `apply` and `snapshot upcoming`.
- `snapshot_retention` is global fallback retention when no tier-specific value is set.
- `default_retention_tier` + `snapshot_retention_tiers` drive defaults for `snapshot prune` and `snapshot archive`.
- `ci_failure_policy` drives `stave ci gate` behavior in CI.
- `capture_cadence` and `snapshot_filename_template` document/standardize how snapshots are captured and named.

Manage these keys from terminal:

```bash
stave config get max_unsafe
stave config set max_unsafe 72h
stave config set snapshot_retention_tiers.non_critical 14d
```

Supported `stave config get/set` keys:
- `max_unsafe`
- `snapshot_retention`
- `default_retention_tier`
- `ci_failure_policy`
- `capture_cadence`
- `snapshot_filename_template`
- `snapshot_retention_tiers.<tier>`

### Why `daily` vs `hourly` cadence options exist

`stave init --capture-cadence` sets scaffold defaults to avoid ad-hoc snapshot timing:

- `daily`: lower cost and lower noise, good default for most teams.
- `hourly`: tighter feedback loops for critical production incidents and fast-changing environments.

Without a cadence convention, teams capture snapshots irregularly, which makes duration windows less reliable and causes inconsistent CI behavior.

### Safety defaults for destructive commands

Both `snapshot prune` (deletes files) and `snapshot archive` (moves files) share the same safety model:

- **Safe by default**: When neither `--dry-run` nor `--force` is specified, both commands default to a dry run — previewing operations without applying them.
- **Explicit opt-in**: Use `--force` to apply the operation.
- **Minimum retention**: Both keep at least `--keep-min` snapshots (default: 2), regardless of age filters.

### Lifecycle command examples

```bash
# Generate action items and CI summary
stave snapshot upcoming \
  --controls ./controls \
  --observations ./observations \
  --due-soon 24h \
  --status OVERDUE \
  --control-id CTL.S3.PUBLIC.001 \
  --format json \
  --out output/upcoming.md \
  --summary-out "$GITHUB_STEP_SUMMARY"

# Prune old snapshots (preview first)
stave snapshot prune --observations ./observations --older-than 30d --dry-run
stave snapshot prune --observations ./observations --older-than 30d --force
stave snapshot prune --observations ./observations --older-than 30d --dry-run --format json

# Tier-based retention (reads snapshot_retention_tiers from stave.yaml)
stave snapshot prune --observations ./observations --retention-tier non_critical --dry-run

# Archive old snapshots instead of deleting
stave snapshot archive --observations ./observations --archive-dir ./observations/archive --older-than 30d --dry-run
stave snapshot archive --observations ./observations --archive-dir ./observations/archive --older-than 30d --force
stave snapshot archive --observations ./observations --archive-dir ./observations/archive --retention-tier critical --dry-run
stave snapshot archive --observations ./observations --archive-dir ./observations/archive --older-than 30d --dry-run --format json

# Diff latest two snapshots
stave snapshot diff --observations ./observations --format json --out output/diff.json

# Diff filters for focused triage
stave snapshot diff --observations ./observations --change-type modified --asset-type res:aws:s3:bucket --asset-id prod-

# Quality gate before evaluation
stave snapshot quality --observations ./observations --strict

# Weekly hygiene report (markdown)
stave snapshot hygiene \
  --controls ./controls \
  --observations ./observations \
  --archive-dir ./observations/archive \
  --out output/weekly-hygiene.md

# Weekly hygiene report (json)
stave snapshot hygiene \
  --controls ./controls \
  --observations ./observations \
  --format json \
  --out output/weekly-hygiene.json

# Filter hygiene upcoming metrics
stave snapshot hygiene \
  --controls ./controls \
  --observations ./observations \
  --status OVERDUE \
  --control-id CTL.S3.PUBLIC.001

# Baseline for fail-on-new CI policy
stave ci baseline save --in output/evaluation.json --out output/baseline.json
stave ci baseline check --in output/evaluation.json --baseline output/baseline.json --fail-on-new

# Policy-driven CI gate from stave.yaml defaults
stave ci gate --in output/evaluation.json --baseline output/baseline.json

# Run full fix verification loop and generate remediation artifacts
stave ci fix-loop \
  --before ./obs-before \
  --after ./obs-after \
  --controls ./controls \
  --out output
```

### CI failure policy modes

`stave ci gate --policy ...` supports:

- `fail_on_any_violation`: fail when current evaluation has any findings.
- `fail_on_new_violation`: fail only when findings are new compared to baseline.
- `fail_on_overdue_upcoming`: fail when snapshot action items are already overdue.

You can set project default in `stave.yaml` and override per-run via:
- config: `ci_failure_policy: fail_on_new_violation`
- env override: `STAVE_CI_FAILURE_POLICY=fail_on_overdue_upcoming`

## Command Composition

Stave commands produce structured output (JSON to stdout) and accept structured input (via `--in`, `--previous-output`, or `-` for stdin). This lets you chain commands with Unix pipes.

### Stdin Convention

`-` means "read from stdin" on flags that accept file paths:

- `stave validate --in -` — validate from stdin
- `stave diagnose --previous-output -` — read prior apply output from stdin

### File-Mediated Pipelines for CI

The default CI pattern saves intermediate results to files:

```bash
stave apply ... --format json > output/evaluation.json
stave ci gate --in output/evaluation.json
stave report --in output/evaluation.json
stave fix --input output/evaluation.json --finding CTL.S3.PUBLIC.001@my-bucket
stave enforce --in output/evaluation.json --mode pab
```

### Live Pipe Examples

```bash
# Pipe apply output into diagnose
stave apply --controls controls/s3 --observations observations/ --max-unsafe 168h \
| stave diagnose --previous-output - --controls controls/s3 --observations observations/

# Extract control IDs from findings
stave apply --controls controls/s3 --observations observations/ --max-unsafe 168h \
| jq '.findings[].control_id'

# Render coverage graph as PNG
stave graph coverage --controls controls/s3 --observations observations/ \
| dot -Tpng > coverage.png

# Validate a control from stdin
cat controls/s3/CTL.S3.PUBLIC.001.yaml | stave validate --in -
```

### Composition Reference

| Command | Produces | Consumes | Input Flag |
|---------|----------|----------|------------|
| `apply` | `out.v0.1` JSON | controls + observations | `--controls`, `--observations` |
| `diagnose` | diagnostic JSON/text | controls + observations + prior output | `--previous-output` (accepts `-`) |
| `validate` | validation JSON/text | single file or dirs | `--in` (accepts `-`) |
| `report` | markdown/text | evaluation JSON | `--in` |
| `enforce` | Terraform/SCP artifacts | evaluation JSON | `--in` |
| `fix` | remediation text | evaluation JSON | `--input` |
| `ci gate` | pass/fail | evaluation JSON | `--in` |
| `graph coverage` | DOT/JSON | controls + observations | `--controls`, `--observations` |

## Commands

### validate

Checks that inputs are well-formed and consistent as a pre-evaluation validation step.

```bash
stave validate [flags]
```

**Purpose:** Verify inputs are sound before evaluation.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--observations` | `observations` | Path to observation snapshots directory |
| `--max-unsafe` | `168h` | Maximum allowed unsafe duration |
| `--now` | (current time) | Override evaluation time (RFC3339 format) |
| `--format` | `text` | Output format: `text` or `json` |
| `--strict` | `false` | Treat warnings as errors (exit 2) |
| `--fix-hints` | `false` | Print command-level remediation hints |
| `--quiet` | `false` | Suppress output (exit code only) |
| `--in` | (none) | Validate a single file path (or `-` for stdin) |
| `--template` | (none) | Go-style template string for custom output (bypasses --format) |

**What it checks:**

| Category | Checks |
|----------|--------|
| Controls | Schema validation, required fields (id, name, description), ID format |
| Observations | Schema validation, timestamps, asset IDs |
| Time sanity | Snapshots sorted, unique timestamps, --now >= latest snapshot |
| Consistency | Predicate references valid params, duration feasibility |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All inputs valid (no errors, no warnings) |
| 2 | Validation errors or warnings found |

**Examples:**

```bash
# Basic validation
stave validate

# Custom directories
stave validate \
  --controls ./my-controls \
  --observations ./snapshots

# JSON output (for CI parsing)
stave validate --format json

# Validate a single file
stave validate --in ./observations/2026-01-11T000000Z.json
```

**Output Format (text):**

```
Validation passed (2 warnings)

WARNING: SPAN_LESS_THAN_MAX_UNSAFE
  span=24h0m0s
  max_unsafe=168h0m0s
  Fix: Add older snapshots or reduce --max-unsafe

WARNING: ASSET_SINGLE_APPEARANCE
  asset_id=res-123
  Fix: Duration tracking requires asset to appear in multiple snapshots

---
Checked: 2 controls, 2 snapshots, 3 assets
```

**Output Format (JSON):**

```json
{
  "valid": true,
  "warnings": [
    {
      "code": "SPAN_LESS_THAN_MAX_UNSAFE",
      "signal": "warning",
      "evidence": {"span": "24h0m0s", "max_unsafe": "168h0m0s"},
      "action": "Add older snapshots or reduce --max-unsafe"
    }
  ],
  "summary": {
    "controls_checked": 2,
    "snapshots_checked": 2,
    "resources_checked": 3
  }
}
```

**Validation Codes:**

| Code | Signal | Meaning |
|------|--------|---------|
| `CONTROL_MISSING_ID` | error | Control missing required `id` field |
| `CONTROL_MISSING_NAME` | error | Control missing required `name` field |
| `NOW_BEFORE_SNAPSHOTS` | error | `--now` must be at or after the latest snapshot |
| `SINGLE_SNAPSHOT` | warning | Only 1 snapshot (need 2+ for duration tracking) |
| `SPAN_LESS_THAN_MAX_UNSAFE` | warning | Snapshot span shorter than threshold |
| `CONTROL_NEVER_MATCHES` | warning | No assets match unsafe_predicate |

### apply

Evaluates configuration snapshots against safety controls.

```bash
stave apply [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--observations` | `observations` | Path to observation snapshots directory |
| `--max-unsafe` | `168h` | Maximum allowed unsafe duration |
| `--now` | (current time) | Override evaluation time (RFC3339 format) |
| `--allow-unknown-input` | `false` | Allow observations with unknown source types |
| `--integrity-manifest` | (none) | Verify loaded observation files against expected SHA-256 hashes in a manifest JSON |
| `--integrity-public-key` | (none) | Verify signed manifest with Ed25519 public key (requires `--integrity-manifest`) |
| `--template` | (none) | Go-style template string for custom output (bypasses --format) |
| `--min-severity` | (none) | Only evaluate controls at or above this severity level |
| `--control-id` | (none) | Evaluate only this specific control |
| `--exclude-control-id` | (none) | Exclude specific controls (repeatable) |
| `--compliance` | (none) | Only evaluate controls mapped to this compliance framework |

**Duration Format:**

- Hours: `24h`, `168h`, `720h`
- Days: `1d`, `7d`, `30d`
- Combined: `1h30m`

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Success, no violations found |
| 2 | Error (invalid input, missing files, schema invalid) |
| 3 | Success, violations found |

**Examples:**

```bash
# Basic evaluation
stave apply

# Custom directories
stave apply \
  --controls ./my-controls \
  --observations ./snapshots

# 7-day threshold
stave apply --max-unsafe 7d

# Deterministic evaluation (for CI/testing)
stave apply --now 2026-01-15T00:00:00Z

# Allow unknown source types
stave apply --allow-unknown-input

# Integrity-checked evaluation (unsigned manifest)
stave apply \
  --controls ./my-controls \
  --observations ./snapshots \
  --integrity-manifest ./observations.manifest.json

# Integrity-checked evaluation (signed manifest)
stave apply \
  --controls ./my-controls \
  --observations ./snapshots \
  --integrity-manifest ./observations.signed-manifest.json \
  --integrity-public-key ./observations.pub
```

**Manifest format**
```json
{
  "files": {
    "2026-01-01T000000Z.json": "<sha256-hex>"
  },
  "overall": "<sha256-hex>"
}
```

Notes:
- `--integrity-public-key` can only be used with `--integrity-manifest`.
- Integrity verification is not supported with `--observations -` (stdin mode).
- Any mismatch (missing/extra file, wrong hash, invalid signature) fails evaluation before control execution.

### capabilities

Displays supported versions and input types.

```bash
stave capabilities
```

**Output:**

```json
{
  "version": "0.1.0",
  "offline": true,
  "observations": {
    "schema_versions": ["obs.v0.1"]
  },
  "controls": {
    "dsl_versions": ["ctrl.v1"]
  },
  "inputs": {
    "source_types": [
      {
        "type": "terraform.plan_json",
        "description": "Terraform plan JSON output",
        "tool_min_version": "1.5.0",
        "plan_format": "terraform show -json"
      },
      {
        "type": "aws-s3-snapshot",
        "description": "S3 snapshot JSON observations"
      }
    ]
  },
  "packs": [
    {
      "name": "s3",
      "path": "controls/s3",
      "version": "0.1.0"
    }
  ],
  "security_audit": {
    "enabled": true,
    "formats": ["json", "markdown", "sarif"],
    "sbom_formats": ["spdx", "cyclonedx"],
    "vuln_sources": ["hybrid", "local", "ci"],
    "fail_on_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
    "compliance_frameworks": ["nist_800_53", "cis_aws_v1.4.0", "soc2", "pci_dss_v3.2.1"]
  }
}
```

**Packs:** The `packs` field lists available control packs. Each pack includes:
- `name`: Pack identifier
- `path`: Directory containing pack controls
- `version`: Pack version

### inspect

Low-level domain analysis primitives. Each subcommand reads JSON from `--file` or stdin and outputs JSON. These are building blocks for custom tooling.

```bash
stave inspect <subcommand> [flags]
```

**Subcommands:**

| Subcommand | Purpose | Input |
|------------|---------|-------|
| `policy` | S3 bucket policy analysis | Raw bucket policy JSON |
| `acl` | S3 ACL grant analysis | JSON array of grants |
| `exposure` | Exposure classification | Normalized resource inputs |
| `risk` | Risk scoring | Statement context JSON |
| `compliance` | Compliance framework crosswalk | Crosswalk YAML (`--file`, required) |
| `aliases` | Predicate alias listing | None (optional `--category`) |

**Examples:**

```bash
# Analyze a bucket policy
stave inspect policy --file policy.json

# Pipe ACL grants from stdin
cat grants.json | stave inspect acl

# Resolve compliance crosswalk for NIST
stave inspect compliance --file crosswalk.yaml --framework nist_800_53

# List all predicate aliases
stave inspect aliases
```

### diagnose

Analyzes evaluation inputs and results to identify likely causes when results don't match expectations.

```bash
stave diagnose [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--observations` | `observations` | Path to observation snapshots directory |
| `--previous-output` | (none) | Path to existing apply output JSON |
| `--max-unsafe` | `168h` | Maximum allowed unsafe duration |
| `--now` | (current time) | Override evaluation time (RFC3339 format) |
| `--format` | `text` | Output format: `text` or `json` |
| `--quiet` | `false` | Suppress output (exit code only) |
| `--case` | (none) | Filter diagnostics to one or more case values |
| `--signal-contains` | (none) | Filter diagnostics by signal substring (case-insensitive) |
| `--template` | (none) | Go-style template string for custom output (bypasses --format) |

**What it checks:**

| Scenario | Checks |
|----------|--------|
| Expected violations but got none | Threshold mismatch, time span too short, predicate mismatch |
| Unexpected violations | Clock skew, streak evidence, reset detection |
| Empty findings array | No predicate matches, under threshold, became safe |

**Examples:**

```bash
# Basic diagnosis
stave diagnose \
  --controls controls/s3 \
  --observations examples/observations/

# Diagnose with specific threshold
stave diagnose --max-unsafe 7d

# Diagnose existing output file
stave diagnose --previous-output previous-run.json

# Deterministic diagnosis (for CI)
stave diagnose --now 2026-01-15T00:00:00Z

# JSON output for scripting
stave diagnose --format json
```

**Output format:**

```
=== Diagnostic Summary ===

Snapshots:    3
Resources:    2
Controls:   2
Time span:    10d
Threshold:    7d
Violations:   1
Attack surface: 1

=== Diagnostics (1) ===

--- [1] expected_violations_none ---
Signal:   Threshold exceeds observed unsafe duration
Evidence: Max unsafe streak: 48h; threshold: 168h
Action:   Lower --max-unsafe to 48h or shorter
Command:  stave apply --max-unsafe 48h
```

**Common diagnostic signals:**

| Signal | Meaning | Action |
|--------|---------|--------|
| Threshold exceeds observed unsafe duration | Resources are unsafe but not long enough | Lower `--max-unsafe` |
| Time span shorter than threshold | Snapshot coverage window is shorter than the configured threshold | Collect more snapshots |
| No assets matched unsafe_predicate | Predicate doesn't match any assets | Check extractor or predicate |
| Evaluation time before latest snapshot | `--now` is set incorrectly | Fix `--now` timestamp |
| Streak reset detected | Resource became safe briefly | Expected behavior |

### graph coverage

Shows which controls cover which assets by testing each control's `unsafe_predicate` against assets from the latest observation snapshot.

```bash
stave graph coverage [flags]
```

**Purpose:** Visualize policy coverage — find uncovered assets, see control scope, and understand protection density.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--observations` | `observations` | Path to observation snapshots directory |
| `--format` | `dot` | Output format: `dot` or `json` |
| `--allow-unknown-input` | `false` | Allow observations with unknown source types |
| `--sanitize` | `false` | Sanitize asset identifiers (global flag) |

**Examples:**

```bash
# Output DOT graph to stdout
stave graph coverage --controls ./controls --observations ./obs

# Render as PNG (requires graphviz)
stave graph coverage --controls ./controls --observations ./obs | dot -Tpng > coverage.png

# JSON output for scripting
stave graph coverage --controls ./controls --observations ./obs --format json | jq .

# Sanitize asset identifiers for sharing
stave graph coverage --controls ./controls --observations ./obs --sanitize
```

**DOT output** includes:
- Control nodes (lightblue) in a cluster
- Resource nodes in a cluster (uncovered assets highlighted in lightyellow)
- Directed edges from controls to matching assets

**JSON output** structure:

```json
{
  "controls": ["CTL.S3.PUBLIC.001", "..."],
  "assets": ["res:aws:s3:bucket:prod-data", "..."],
  "edges": [
    {"control_id": "CTL.S3.PUBLIC.001", "asset_id": "res:aws:s3:bucket:prod-data"}
  ],
  "uncovered_assets": ["res:aws:s3:bucket:staging-logs"]
}
```

### report

Generates a plain-text markdown report from evaluation JSON output. The findings section uses TSV (tab-separated values) so that `grep`, `sort`, `awk`, and `head` work naturally.

```bash
stave report [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--in` / `-i` | (required) | Path to evaluation JSON file |
| `--out` / `-o` | (none) | Write report to file |
| `--format` / `-f` | `text` | Output format: `text` or `json` |

**Examples:**

```bash
# Generate report from evaluation output
stave report --in evaluation.json

# Write report to file
stave report --in evaluation.json --out report.md

# Filter findings by control pattern
stave report --in evaluation.json | grep '^CTL.S3.PUBLIC'

# Sort findings by duration (longest first)
stave report --in evaluation.json | awk '/^CTL\./' | sort -t$'\t' -k5 -nr

# Top 5 longest-running violations
stave report --in evaluation.json | awk '/^CTL\./' | sort -t$'\t' -k5 -nr | head -5

# Count violations per control
stave report --in evaluation.json | awk -F'\t' '/^CTL\./{print $1}' | sort | uniq -c | sort -rn

# JSON output for programmatic consumption
stave report --in evaluation.json --format json
```

**TSV columns:**

| Column | Description |
|--------|-------------|
| `CONTROL_ID` | Control identifier |
| `RESOURCE_ID` | Resource identifier |
| `TYPE` | Resource type |
| `VENDOR` | Cloud vendor |
| `SEVERITY` | Control severity level |
| `DURATION_H` | Unsafe duration in hours |
| `THRESHOLD_H` | Threshold in hours |
| `FIRST_UNSAFE` | First unsafe timestamp (RFC3339) |
| `LAST_UNSAFE` | Last unsafe timestamp (RFC3339) |

Data lines start with `CTL.`, making `awk '/^CTL\./'` a reliable filter for extracting data rows.

### alias

Manage command aliases stored in user config (`~/.config/stave/config.yaml`).

```bash
stave alias <subcommand>
```

**Subcommands:**

| Subcommand | Usage | Description |
|------------|-------|-------------|
| `set` | `stave alias set <name> "<command>"` | Create or update an alias |
| `list` | `stave alias list` | List all defined aliases |
| `delete` | `stave alias delete <name>` | Delete an alias |

Alias names must match `[a-zA-Z0-9_-]+` and must not collide with existing command names.

**Examples:**

```bash
# Create an alias for a common evaluation command
stave alias set ev "apply --controls controls/s3 --observations observations --max-unsafe 24h"

# Use the alias (appends extra flags)
stave ev --now 2026-01-15T00:00:00Z

# List all aliases
stave alias list

# JSON output
stave alias list --format json

# Delete an alias
stave alias delete ev
```

### status

Shows your current project state and recommends the next command to run. Use this when resuming work or when you're unsure what step comes next.

```bash
stave status [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `text` | Output format: `text` or `json` |

**Examples:**

```bash
# See where you are and what to do next
stave status

# JSON output for scripting
stave status --format json
```

**Output (text):**

```
Summary
-------
Project: /path/to/project
Last command: apply (2026-01-15T00:00:00Z)
Artifacts:
  - controls: 35
  - snapshots/raw: 2
  - observations: 2
  - output/evaluation.json: true

[INFO] Next: stave diagnose --controls ./controls --observations ./observations
```

---

### doctor

Checks environment readiness for running Stave.

```bash
stave doctor
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All checks pass |
| 2 | One or more checks failed |

**Examples:**

```bash
stave doctor
```

Output shows `[PASS]`, `[WARN]`, or `[FAIL]` for each check (Go version, required tools, project structure).

---

### init

Scaffolds a new Stave project directory with controls, observations, and config.

```bash
stave init [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | (none) | Project profile (e.g., `aws-s3`) |
| `--dir` | `.` | Target directory |
| `--dry-run` | `false` | Preview without creating files |
| `--with-github-actions` | `false` | Include GitHub Actions workflow |
| `--capture-cadence` | `daily` | Snapshot capture cadence (`daily` or `hourly`) |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Project created |
| 2 | Invalid flags or target exists |

**Examples:**

```bash
stave init --profile aws-s3 --dir my-project
stave init --profile aws-s3 --with-github-actions
stave init --dry-run
```

---

### generate

Generates starter control or observation templates.

```bash
stave generate <subcommand>
```

**Subcommands:**

| Subcommand | Usage | Description |
|------------|-------|-------------|
| `control` | `stave generate control` | Generate a minimal control YAML template |
| `observation` | `stave generate observation` | Generate a minimal observation JSON template |

**Examples:**

```bash
stave generate control > controls/my-new-control.yaml
stave generate observation > observations/template.json
```

---

### plan

Readiness gate before running `apply`. Checks prerequisites and input readiness.

```bash
stave plan [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--observations` | `observations` | Path to observation snapshots directory |
| `--format` | `text` | Output format: `text` or `json` |
| `--now` | (current time) | Override evaluation time |
| `--max-unsafe` | `168h` | Maximum allowed unsafe duration |
| `--quiet` | `false` | Suppress output (exit code only) |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Ready to apply |
| 2 | Blockers found (missing inputs, schema issues) |

**Examples:**

```bash
stave plan
stave plan --controls ./controls --observations ./observations
stave plan --format json
```

---

### explain

Shows what fields a control needs from observations, helping you understand predicate requirements.

```bash
stave explain <control-id> [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--format` | `text` | Output format: `text` or `json` |

**Examples:**

```bash
stave explain CTL.S3.PUBLIC.001
stave explain CTL.S3.PUBLIC.001 --controls ./my-controls
stave explain CTL.S3.PUBLIC.001 --format json
```

---

### fmt

Deterministic formatting for control YAML and observation JSON files.

```bash
stave fmt [path] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--check` | `false` | Check formatting without modifying (exit 1 if changes needed) |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Files formatted (or already formatted with `--check`) |
| 1 | Files need formatting (`--check` mode) |

**Examples:**

```bash
stave fmt controls/s3/
stave fmt controls/s3/CTL.S3.PUBLIC.001.yaml
stave fmt --check controls/s3/
```

---

### lint

Validates control design quality rules.

```bash
stave lint [path]
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All quality checks pass |
| 2 | Quality issues found |

**Examples:**

```bash
stave lint controls/s3/
stave lint controls/s3/CTL.S3.PUBLIC.001.yaml
```

---

### trace

Step-by-step PASS/FAIL trace of a single control against a single asset. Use for debugging why a control matches or doesn't match.

```bash
stave trace [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--control` | (required) | Control ID to trace |
| `--observation` | (required) | Path to a single observation file |
| `--asset-id` | (required) | Resource/asset ID to trace against |
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--format` | `text` | Output format: `text` or `json` |

**Examples:**

```bash
stave trace \
  --control CTL.S3.PUBLIC.001 \
  --observation observations/2026-01-15T000000Z.json \
  --asset-id my-bucket

stave trace \
  --control CTL.S3.PUBLIC.001 \
  --observation observations/2026-01-15T000000Z.json \
  --asset-id my-bucket \
  --format json
```

---

### verify

Compares before/after observations to confirm a remediation resolved violations.

```bash
stave verify [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--before` | (required) | Path to before-state observations directory |
| `--after` | (required) | Path to after-state observations directory |
| `--controls` | `controls/s3` | Path to control definitions directory |
| `--now` | (current time) | Override evaluation time |
| `--max-unsafe` | `168h` | Maximum allowed unsafe duration |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All violations resolved, none introduced |
| 3 | Remaining or new violations |

**Examples:**

```bash
stave verify \
  --before ./obs-before \
  --after ./obs-after \
  --controls controls/s3 \
  --now 2026-01-15T00:00:00Z
```

---

### enforce

Generates remediation templates from evaluation output.

```bash
stave enforce [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--in` | (required) | Path to evaluation JSON file |
| `--mode` | `pab` | Enforcement mode: `pab` (put-account-block) or `scp` (service control policy) |
| `--out` | (none) | Output directory |
| `--dry-run` | `false` | Preview without creating files |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Artifacts generated |
| 2 | Invalid input |

**Examples:**

```bash
stave enforce --in output/evaluation.json --mode pab --out output/enforcement
stave enforce --in output/evaluation.json --mode scp --out output/enforcement
stave enforce --in output/evaluation.json --dry-run
```

---

### controls

Browse and manage controls.

```bash
stave controls <subcommand>
```

**Subcommands:**

| Subcommand | Usage | Description |
|------------|-------|-------------|
| `list` | `stave controls list` | List all available controls |
| `explain` | `stave controls explain <id>` | Explain a specific control |
| `aliases` | `stave controls aliases` | List control ID aliases |
| `alias-explain` | `stave controls alias-explain <alias>` | Explain what an alias resolves to |

**Examples:**

```bash
stave controls list
stave controls list --format json
stave controls explain CTL.S3.PUBLIC.001
stave controls aliases
```

---

### packs

Browse available control packs.

```bash
stave packs <subcommand>
```

**Subcommands:**

| Subcommand | Usage | Description |
|------------|-------|-------------|
| `list` | `stave packs list` | List available control packs |
| `show` | `stave packs show <name>` | Show details of a pack |

**Examples:**

```bash
stave packs list
stave packs show s3
```

---

### fix

Shows remediation guidance for a specific finding from evaluation output.

```bash
stave fix [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | (required) | Path to evaluation JSON file |
| `--finding` | (required) | Finding identifier (`<control-id>@<asset-id>`) |

**Examples:**

```bash
stave fix --input output/evaluation.json --finding CTL.S3.PUBLIC.001@my-bucket
```

---

### bug-report

Collects diagnostic information for filing bug reports.

```bash
stave bug-report [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `bug-report.zip` | Output file path |
| `--include-config` | `false` | Include project config in bundle |
| `--tail-lines` | `100` | Number of recent log lines to include |

**Examples:**

```bash
stave bug-report
stave bug-report --out my-bug.zip --include-config
```

---

### prompt from-finding

Generates an LLM prompt from evaluation findings.

```bash
stave prompt from-finding [flags]
```

**Examples:**

```bash
stave prompt from-finding --input output/evaluation.json
```

---

### env list

Lists supported STAVE_* environment variables.

```bash
stave env list
```

---

### schemas

Lists wire-format contract schemas.

```bash
stave schemas
```

---

### version

Prints version information.

```bash
stave version
```

Note: Also available as the `--version` global flag (`stave --version`).

### Output Templating (`--template`)

The `apply`, `diagnose`, and `validate` commands accept a `--template` flag for custom output formatting. Templates bypass `--format` and render directly against the command's output struct.

**Supported syntax:**

| Syntax | Description |
|--------|-------------|
| `{{.FieldName}}` | Access a top-level field |
| `{{.Nested.FieldName}}` | Access nested fields |
| `{{range .Slice}}...{{end}}` | Iterate over slices |
| `{{json .Field}}` | JSON-encode a field value |
| `{{"\n"}}` | Literal newline |

Fields resolve by struct field name or JSON tag name.

**Examples:**

```bash
# Count violations
stave apply --controls ./controls --observations ./obs \
  --template '{{.Summary.Violations}} violations, {{.Summary.AssetsEvaluated}} assets'

# CSV of violated control + asset
stave apply --controls ./controls --observations ./obs \
  --template '{{range .Violations}}{{.ControlID}},{{.AssetID}}{{"\n"}}{{end}}'

# Diagnose summary line
stave diagnose --controls ./controls --observations ./obs \
  --template '{{.Report.Summary.Snapshots}} snapshots, {{.Report.Summary.Diagnostics}} diagnostics'

# Validate summary as JSON
stave validate --controls ./controls --observations ./obs \
  --template '{{json .Summary}}'
```

## Input Files

### Observation Snapshots

Observations capture the state of your infrastructure at a point in time.

**Location:** `examples/observations/` directory (or custom path via `--observations`)

**File naming:** Use RFC3339 timestamps for deterministic ordering:
- `2026-01-01T000000Z.json`
- `2026-01-15T123000Z.json`

**Schema:**

```json
{
  "schema_version": "obs.v0.1",
  "generated_by": {
    "source_type": "terraform.plan_json",
    "tool": "terraform",
    "tool_version": "1.6.3",
    "provider": "hashicorp/aws",
    "provider_version": "5.31.0"
  },
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {
      "id": "res:aws:s3:bucket:my-bucket",
      "type": "storage_bucket",
      "vendor": "aws",
      "properties": {
        "public": true,
        "acl": "public-read"
      },
      "source": {
        "file": "infra/main.tf",
        "line": 42
      }
    }
  ]
}
```

**Required Fields:**

| Field | Description |
|-------|-------------|
| `schema_version` | Must be `obs.v0.1` |
| `captured_at` | RFC3339 timestamp of when snapshot was taken |
| `assets[].id` | Unique asset identifier |
| `assets[].type` | Asset type (e.g., `storage_bucket`) |
| `generated_by.source_type` | Required unless `--allow-unknown-input` is set |

**Optional Fields:**

| Field | Description |
|-------|-------------|
| `generated_by.tool` | Tool that generated the snapshot |
| `generated_by.tool_version` | Version of the tool |
| `assets[].vendor` | Cloud provider (e.g., `aws`, `gcp`) |
| `assets[].properties` | Asset configuration properties |
| `assets[].source.file` | Source file path |
| `assets[].source.line` | Line number in source file |

### Control Definitions

Controls define safety rules that assets must satisfy.

**Location:** `controls/s3/` directory (or custom path via `--controls`)

**Schema:**

```yaml
dsl_version: ctrl.v1
id: CTL.EXP.DURATION.001
name: Unsafe Duration Bound
description: An asset must not remain unsafe beyond the configured time window.
type: unsafe_duration
params:
  max_unsafe_duration: "168h"
unsafe_predicate:
  any:
    - field: "properties.public"
      op: "eq"
      value: true
```

**Required Fields:**

| Field | Description |
|-------|-------------|
| `dsl_version` | Must be `ctrl.v1` |
| `id` | Unique control identifier |
| `name` | Human-readable name |
| `unsafe_predicate.any` | List of conditions (OR logic) |

**Predicate Rules:**

Each rule in `unsafe_predicate.any` checks an asset property:

```yaml
unsafe_predicate:
  any:
    - field: "properties.public"    # Dot-notation path
      op: "eq"                       # Operator
      value: true                    # Expected value
```

**Supported Operators:**

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

**Field Paths:**

Use dot notation to access nested properties:
- `properties.public`
- `properties.encryption.enabled`
- `properties.tags.environment`

## Output Format

### JSON Output

```json
{
  "run": {
    "now": "2026-01-11T00:00:00Z",
    "max_unsafe": "168h0m0s",
    "snapshots": 3
  },
  "summary": {
    "assets_evaluated": 2,
    "attack_surface": 1,
    "violations": 1
  },
  "findings": [
    {
      "control_id": "CTL.EXP.DURATION.001",
      "control_name": "Unsafe Duration Bound",
      "control_description": "An asset must not remain unsafe beyond the configured time window.",
      "asset_id": "res:aws:s3:bucket:public-bucket",
      "asset_type": "storage_bucket",
      "asset_vendor": "aws",
      "source": {
        "file": "infra/main.tf",
        "line": 42
      },
      "evidence": {
        "first_unsafe_at": "2026-01-01T00:00:00Z",
        "last_seen_unsafe_at": "2026-01-11T00:00:00Z",
        "unsafe_duration_hours": 240,
        "threshold_hours": 168
      },
      "remediation": {
        "description": "Resource has been unsafe beyond the allowed duration threshold.",
        "action": "Review and remediate the unsafe configuration, then verify in a new snapshot."
      }
    }
  ]
}
```

### Output Fields

**run:** Evaluation context
- `now`: Evaluation timestamp
- `max_unsafe`: Configured threshold
- `snapshots`: Number of snapshots processed

**summary:** Aggregate statistics
- `assets_evaluated`: Total unique assets seen
- `attack_surface`: Resources unsafe in latest snapshot
- `violations`: Resources exceeding threshold

**findings[]:** Violation details
- `evidence.first_unsafe_at`: When asset first became unsafe
- `evidence.last_seen_unsafe_at`: Most recent unsafe observation
- `evidence.unsafe_duration_hours`: How long asset has been unsafe
- `evidence.threshold_hours`: Configured maximum

## How It Works

### Unsafe Duration Tracking

Stave tracks how long each asset has been continuously unsafe:

1. **Load snapshots** ordered by `captured_at`
2. **Build timeline** for each asset across snapshots
3. **Track unsafe windows**:
   - When asset matches `unsafe_predicate` → start/continue window
   - When asset becomes safe → reset window
4. **Report violations** where `unsafe_duration > max_unsafe`

### Window Reset Behavior

If an asset becomes safe and then unsafe again, the timer resets:

```
Snapshot 1 (Jan 1):  public=true   → unsafe window starts
Snapshot 2 (Jan 10): public=false  → window RESETS (asset is safe)
Snapshot 3 (Jan 11): public=true   → NEW unsafe window starts (only 1 day)
```

This prevents false positives when issues are temporarily fixed.

## CI/CD Integration

### Basic Pipeline

```bash
#!/bin/bash
set -e

# Build
make build

# Run evaluation
./stave apply \
  --controls controls/s3 \
  --observations examples/observations/ \
  --max-unsafe 7d \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Exit code 3 = violations found (fail the build)
```

### GitHub Actions

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  stave:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26.1'

      - name: Build Stave
        run: make build

      - name: Run Stave
        run: |
          ./stave apply \
            --controls controls/s3 \
            --observations examples/observations/ \
            --max-unsafe 168h
```

### Generating Snapshots

Create a script to generate snapshots from Terraform:

```bash
#!/bin/bash
# generate-snapshot.sh

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT="observations/${TIMESTAMP}.json"

terraform show -json > terraform-output.json

# Transform to Stave format (implement your transformer)
./transform-terraform.sh terraform-output.json > "$OUTPUT"

echo "Generated: $OUTPUT"
```

## Best Practices

1. **Use deterministic timestamps** for CI: Always pass `--now` in automated pipelines for reproducible results.

2. **Name snapshots with timestamps**: Use RFC3339 format (`2026-01-01T000000Z.json`) for automatic ordering.

3. **Keep multiple snapshots**: Stave needs historical data to calculate durations. Keep at least 2-3 weeks of snapshots.

4. **Start with longer thresholds**: Begin with `30d` and tighten to `7d` as your remediation process matures.

5. **Version your controls**: Store control definitions in version control alongside your infrastructure code.

6. **Automate snapshot generation**: Integrate snapshot generation into your CI/CD pipeline after Terraform plans.

## Troubleshooting

### No violations reported but expected

1. Check `--max-unsafe` threshold—is it longer than the actual unsafe duration?
2. Verify `captured_at` timestamps span enough time
3. Confirm `unsafe_predicate` matches your asset properties

### Unexpected violations

1. Check if asset was briefly safe (resets the window)
2. Verify `--now` time if using deterministic mode
3. Review `evidence.first_unsafe_at` in output

### Empty findings array

This is normal when:
- No assets match the `unsafe_predicate`
- Matching assets haven't exceeded `max_unsafe`
- Resources became safe before the threshold

## S3 Healthcare Profile (MVP 1.0)

Stave includes a dedicated S3 healthcare evaluation profile for HIPAA compliance. This profile provides two specialized commands and 20 controls covering public exposure, encryption, versioning, logging, access control, network scoping, lifecycle retention, and object lock (WORM).

### Quick Start: S3 with Terraform

The most common workflow evaluates S3 buckets from Terraform plan JSON:

```bash
# Generate Terraform plan JSON
terraform plan -out=tfplan
terraform show -json tfplan > terraform-plan.json

# Evaluate against all S3 controls
stave apply \
  --controls controls/s3 \
  --observations ./observations \
  --max-unsafe 168h
```

### apply --profile aws-s3

Evaluates S3 observations against the built-in PHI control profile (`controls/storage/object_storage/s3/`).

```bash
stave apply --profile aws-s3 --input observations.json
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

### S3 Control Catalogue

**Public Exposure:**

| ID | Name |
|----|------|
| `CTL.S3.PUBLIC.001` | No Public Read Access to PHI S3 Data |
| `CTL.S3.PUBLIC.002` | No Public List Access to PHI S3 Buckets |
| `CTL.S3.PUBLIC.003` | No Public Write Access |
| `CTL.S3.PUBLIC.004` | No Public ACL for PHI S3 Buckets |
| `CTL.S3.PUBLIC.PREFIX.001` | Protected Prefixes Must Not Be Publicly Readable |
| `CTL.S3.INCOMPLETE.001` | Complete Data Required for Safety Assessment |

**Encryption:**

| ID | Name |
|----|------|
| `CTL.S3.ENCRYPT.001` | Encryption at Rest Required |
| `CTL.S3.ENCRYPT.002` | Transport Encryption Required |
| `CTL.S3.ENCRYPT.003` | PHI Buckets Must Use SSE-KMS with Customer-Managed Key |

**Versioning:**

| ID | Name |
|----|------|
| `CTL.S3.VERSION.001` | Versioning Required |
| `CTL.S3.VERSION.002` | Backup Buckets Must Have MFA Delete Enabled |

**Access Logging:**

| ID | Name |
|----|------|
| `CTL.S3.LOG.001` | Access Logging Required |

**Access Control:**

| ID | Name |
|----|------|
| `CTL.S3.ACCESS.001` | No Unauthorized Cross-Account Access |
| `CTL.S3.ACCESS.002` | No Wildcard Action Policies |

**Network Scoping:**

| ID | Name |
|----|------|
| `CTL.S3.NETWORK.001` | Public-Principal Policies Must Have Network Conditions |

**Lifecycle Rules (HIPAA Data Retention):**

| ID | Name |
|----|------|
| `CTL.S3.LIFECYCLE.001` | Retention-Tagged Buckets Must Have Lifecycle Rules |
| `CTL.S3.LIFECYCLE.002` | PHI Buckets Must Not Expire Data Before Minimum Retention (2190 days) |

**Object Lock / WORM (HIPAA Immutable Storage):**

| ID | Name |
|----|------|
| `CTL.S3.LOCK.001` | Compliance-Tagged Buckets Must Have Object Lock Enabled |
| `CTL.S3.LOCK.002` | PHI Buckets Must Use COMPLIANCE Mode Object Lock |
| `CTL.S3.LOCK.003` | PHI Object Lock Retention Must Meet Minimum Period (2190 days) |

### Terraform Resource Types Supported

The S3 extractor handles these Terraform asset types:

| Terraform Resource Type | Fields Extracted |
|------------------------|-----------------|
| `aws_s3_bucket` | Bucket name, ARN, tags, `object_lock_enabled` |
| `aws_s3_bucket_policy` | Policy statements, public principal detection, network conditions |
| `aws_s3_bucket_acl` | ACL grants, public grantees |
| `aws_s3_bucket_public_access_block` | All four public access block settings |
| `aws_s3_bucket_account_public_access_block` | Account-level public access overrides |
| `aws_s3_bucket_server_side_encryption_configuration` | SSE algorithm, KMS key ID |
| `aws_s3_bucket_versioning` | Versioning status, MFA delete |
| `aws_s3_bucket_logging` | Target bucket, target prefix |
| `aws_s3_bucket_lifecycle_configuration` | Lifecycle rules, expiration days, transitions |
| `aws_s3_bucket_object_lock_configuration` | Lock mode (COMPLIANCE/GOVERNANCE), retention period |

### S3 Canonical Storage Model

The S3 extractor produces a vendor-agnostic canonical model at `properties.storage.*`. See `docs/storage-canonical-model.md` for the complete field reference.

Key field groups:
- `visibility` — Public read/list/write status
- `controls` — Public access block settings
- `encryption` — At-rest algorithm, KMS key, in-transit enforcement
- `versioning` — Versioning status, MFA delete
- `logging` — Access log target bucket and prefix
- `access` — External accounts, wildcard policies
- `policy` — Network condition analysis (IP/VPC scoping)
- `lifecycle` — Rule counts, expiration days, transition detection
- `object_lock` — Lock mode, retention days
- `tags` — Resource tags (used for PHI/compliance scoping)

### Configuring Prefix Exposure (`CTL.S3.PUBLIC.PREFIX.001`)

The prefix exposure control detects when protected S3 object prefixes are publicly readable. Unlike `CTL.S3.PUBLIC.001` which checks bucket-wide public access, this control operates at the prefix level — it can flag `invoices/` as exposed while allowing `images/` to remain intentionally public.

**How it works:** The evaluator inspects bucket policies, ACL grants, and public access block settings to determine effective public read access for each protected prefix. It reports the specific exposure source (policy statement, ACL grant, or missing evidence) in findings.

**Getting started:** The shipped control includes example prefixes that you should customize to match your bucket layout. Edit `controls/s3/public/CTL.S3.PUBLIC.PREFIX.001.yaml` and replace the prefix lists with your own:

```yaml
# controls/s3/public/CTL.S3.PUBLIC.PREFIX.001.yaml
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.PREFIX.001
name: Protected Prefixes Must Not Be Publicly Readable
description: >
  S3 bucket prefixes marked as protected must not be publicly readable.
  Customize the prefix lists below to match your bucket layout.
domain: exposure
scope_tags:
  - aws
  - s3
type: prefix_exposure
params:
  protected_prefixes:          # <- prefixes that must stay private
    - "invoices/"
    - "secrets/"
    - "internal/"
    - "backups/"
  allowed_public_prefixes:     # <- prefixes intentionally public
    - "images/"
    - "static/"
    - "public/"
unsafe_predicate:
  any:
    - field: properties.storage.kind
      op: eq
      value: bucket
```

If `protected_prefixes` is left empty, the control reports a violation with configuration guidance rather than silently passing — ensuring it stays visible until properly configured.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `protected_prefixes` | list of strings | Prefixes that must NOT be publicly readable. Trailing slashes are added automatically. |
| `allowed_public_prefixes` | list of strings | Prefixes that are intentionally public. Used to detect config overlaps. |

**Evaluation logic:**

1. If `protected_prefixes` is empty, the control reports a `not_configured` violation with example configuration.
2. If any protected prefix overlaps with an allowed prefix, a `config_overlap` violation is reported immediately.
3. For each protected prefix, the evaluator checks:
   - **Bucket policies**: Does any `Allow` statement grant `s3:GetObject` to `Principal: "*"` for an asset ARN that covers this prefix?
   - **Public access block**: Does `BlockPublicPolicy` negate policy-based exposure?
   - **ACL grants**: Do any grants to `AllUsers` or `AuthenticatedUsers` allow `READ` or `FULL_CONTROL`?
   - **Missing evidence**: If no policy or ACL data exists, the prefix is treated as exposed (fail-closed).
4. Each violated prefix produces a separate finding with the exposure source in evidence.

**Example findings:**

A bucket with a public policy granting `s3:GetObject` on `arn:aws:s3:::my-bucket/*` to `Principal: "*"` and `invoices/` as a protected prefix produces:

```json
{
  "control_id": "CTL.S3.PUBLIC.PREFIX.001",
  "asset_id": "res:aws:s3:bucket:my-bucket",
  "evidence": {
    "misconfigurations": [
      {"property": "exposure_source", "actual_value": "policy:PublicRead", "operator": "eq", "unsafe_value": "policy:PublicRead"},
      {"property": "protected_prefix", "actual_value": "invoices/", "operator": "eq", "unsafe_value": "invoices/"}
    ],
    "why_now": "Protected prefix \"invoices/\" is publicly readable via policy:PublicRead."
  }
}
```

**Observation requirements:** The evaluator reads these fields from `properties.storage`:

| Field | Source | Used for |
|-------|--------|----------|
| `kind` | Resource type | Trigger predicate (`eq bucket`) |
| `policy_statements[]` | Bucket policy | Public read detection per prefix |
| `public_access_block` | PAB config | Negates policy/ACL exposure |
| `acl_grants[]` | Bucket ACL | Public grantee detection |
