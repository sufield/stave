package initcmd

import (
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/envvar"
)

func scaffoldGitignore() string {
	return `# Stave raw capture inputs (sensitive by default)
snapshots/raw/*
!snapshots/raw/*.sample.*

# Normalized observations often contain resource identifiers
observations/*.json

# Evaluation/diagnostic output artifacts
output/*
!output/.gitkeep

# Local logs
*.log
`
}

func scaffoldReadme(opts scaffoldOptions) string {
	obsConvertCmd := "stave ingest --profile mvp1-s3 --input ./snapshots/raw/snapshot.json --out ./observations"
	if opts.Profile == profileMVP1S3 {
		obsConvertCmd = "stave ingest --profile mvp1-s3 --input ./snapshots/raw/aws-s3 --out ./observations"
	}
	snapshotNameExample := snapshotFilenameExample(opts.CaptureCadence)
	return scaffoldReadmeIntro(opts) +
		scaffoldReadmeWorkflow(opts, obsConvertCmd) +
		scaffoldReadmeTimeline(opts, snapshotNameExample)
}

func scaffoldReadmeIntro(opts scaffoldOptions) string {
	return `# Stave Project Scaffold

This directory was created by ` + "`stave init`" + `.

## MVP operating assumption

This scaffold assumes snapshots are captured from **production** to remediate
**critical issues** quickly. Defaults are optimized for short feedback loops:

- ` + "`stave snapshot upcoming`" + ` for chronological next-snapshot planning
- ` + "`stave snapshot prune`" + ` for bounded snapshot retention
`
}

func scaffoldReadmeWorkflow(opts scaffoldOptions, obsConvertCmd string) string {
	return `
## Recommended workflow

Project-wide unsafe-duration threshold:
` + "```text" + `
` + projectConfigFile + `
max_unsafe: ` + defaultMaxUnsafeDuration + `
snapshot_retention: ` + defaultSnapshotRetention + `
default_retention_tier: ` + defaultRetentionTier + `
snapshot_retention_tiers:
  critical:
    older_than: 30d
    keep_min: 2
  non_critical:
    older_than: 14d
    keep_min: 2
ci_failure_policy: ` + defaultCIFailurePolicy + `
capture_cadence: ` + opts.CaptureCadence + `
snapshot_filename_template: ` + snapshotFilenameTemplate(opts.CaptureCadence) + `
enabled_control_packs:
  - s3
` + "```" + `
Edit this file once to keep ` + "`--max-unsafe`" + ` and ` + "`snapshot prune --older-than`" + ` defaults consistent.

The ` + "`enabled_control_packs`" + ` field activates built-in control checks.
Run ` + "`stave controls list`" + ` to see all available checks.

Optional personal CLI defaults:
` + "```text" + `
cli.yaml
` + "```" + `
Activate it with:
` + "```bash" + `
export ` + envvar.UserConfig.Name + `="$PWD/cli.yaml"
` + "```" + `
Uncomment the ` + "`cli_defaults`" + ` keys you want for this project shell.

1. Add raw snapshots under ` + "`snapshots/raw/`" + ` and convert observations:
` + "```bash" + `
` + obsConvertCmd + `
` + "```" + `

2. Evaluate against built-in checks and diagnose:
` + "```bash" + `
stave apply --observations ./observations --format json > output/evaluation.json
stave diagnose --observations ./observations --previous-output output/evaluation.json
` + "```" + `

3. Add custom controls (optional):
` + "```bash" + `
stave generate control --id CTL.S3.PUBLIC.901 --out controls/MY.CUSTOM.001.yaml
stave apply --controls ./controls --observations ./observations
` + "```" + `
`
}

func scaffoldReadmeTimeline(opts scaffoldOptions, snapshotNameExample string) string {
	return `
## Timeline snapshots

Store multiple observation files in ` + "`observations/`" + ` using timestamp filenames
(example: ` + "`2026-01-11T00:00:00Z.json`" + `, ` + "`2026-01-18T00:00:00Z.json`" + `) to evaluate
unsafe duration windows and compare remediation over time.

Default cadence template:
- cadence: ` + "`" + opts.CaptureCadence + "`" + `
- naming convention: ` + "`observations/" + snapshotNameExample + "`" + `
`
}

func scaffoldUserConfigExample() string {
	return normalizeTemplate(`# Optional user-level defaults for Stave CLI.
# This file is a template to reduce repeated flags in local workflows.
#
# Activate for current shell:
#   export ` + envvar.UserConfig.Name + `="$PWD/cli.yaml"
#
# Uncomment fields you need.

# max_unsafe: 72h
# snapshot_retention: 30d
# default_retention_tier: critical
# ci_failure_policy: fail_on_new_violation

# cli_defaults:
#   output: json
#   quiet: false
#   sanitize: false
#   path_mode: base
#   allow_unknown_input: false
`)
}

func scaffoldLockfile() string {
	return normalizeTemplate(`schema_version: lock.v1
tool:
  name: stave
  version: ` + GetVersion() + `
contracts:
  control: ctrl.v1
  observation: obs.v0.1
  output: out.v0.1
registries: []
`)
}

const templateControlSample = `# ── Stave Control (` + string(kernel.SchemaControl) + `) ──────────────────────────────────────
#
# A control declares a condition that should NEVER be true in
# production. When the condition matches, Stave reports a finding.
#
# Rename this file and uncomment the lines below to create your first
# custom control. Built-in controls (stave controls list) run
# automatically; this file adds project-specific checks.
#
# Reference: https://stavecli.dev/docs/controls-reference/_index
#
# ── Required fields ────────────────────────────────────────────────
#
# dsl_version: ` + string(kernel.SchemaControl) + `
# id: CTL.ACME.HIPAA.001
# name: PHI buckets must enforce AES-256 encryption
# description: >
#   HIPAA requires encryption at rest for any bucket storing
#   protected health information (PHI).
# type: unsafe_state
#
# ── Predicate (when is the resource unsafe?) ───────────────────────
#
# unsafe_predicate:
#   all:                              # AND — every condition must hold
#     - field: properties.tags.data_class
#       op: eq                        # exact match
#       value: phi
#     - any:                          # OR — at least one must hold
#         - field: properties.storage.encryption.algorithm
#           op: ne                    # not equal
#           value: AES256
#         - field: properties.storage.encryption.algorithm
#           op: missing               # field absent entirely
#
# ── Operators ──────────────────────────────────────────────────────
#
#   eq        exact equality           value: true / "AES256" / 42
#   ne        not equal                value: "NONE"
#   missing   field does not exist     (no value key)
#   present   field exists             (no value key)
#   contains  substring match          value: "public"
#   in        value in list            value: ["us-east-1", "eu-west-1"]
#
# Combinators: all (AND), any (OR). Nest freely.
#
# ── Remediation ────────────────────────────────────────────────────
#
# remediation:
#   description: Bucket lacks required encryption for PHI data.
#   action: >
#     Enable default AES-256 encryption on the bucket and
#     re-capture a snapshot to confirm.
#
# params: {}
`

const templateObservationSample = `# ── Stave Observation (` + string(kernel.SchemaObservation) + `) ────────────────────────────────────
#
# An observation is a point-in-time snapshot of your cloud resources.
# Stave evaluates observations against controls to find violations.
#
# File naming convention: YYYY-MM-DDTHH:MM:SSZ.json
#   e.g. snapshots/raw/2026-01-11T00:00:00Z.json
#
# You need at least 2 observation files (two points in time) for
# Stave to calculate unsafe duration windows.
#
# Remove all lines starting with # before use — JSON does not
# support comments.
#
# Reference: https://stavecli.dev/docs/getting-started/quick-start
#
{
  "schema_version": "` + string(kernel.SchemaObservation) + `",
  "generated_by": {
    "source_type": "aws-s3-snapshot",
    "tool": "stave-template"
  },
  "captured_at": "2026-01-11T00:00:00Z",
  "resources": [
    {
      "id": "aws:s3:::example-phi-bucket",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "visibility": {
            "public_read": false,
            "public_list": false,
            "public_write": false
          },
          "encryption": {
            "enabled": true,
            "algorithm": "AES256"
          }
        },
        "tags": {
          "data_class": "phi",
          "environment": "production"
        }
      }
    }
  ]
}
`

const templateStaveConfigSample = `# ── Stave Project Configuration ─────────────────────────────────────
#
# This is a template for the Stave project manifest.
# Copy this file to stave.yaml to define project-wide defaults.
# The active project manifest is stave.yaml (created by stave init).
# This sample documents every available option.
#
# Reference: https://stavecli.dev/docs/cli-reference/stave-config
#
# ── Unsafe duration threshold ──────────────────────────────────────
#
# How long a resource can remain in an unsafe state before Stave
# reports a finding. Accepts Go duration strings: 24h, 168h, 720h.
#
# max_unsafe: 168h
#
# ── Snapshot retention ─────────────────────────────────────────────
#
# Default retention period for pruning old snapshots.
#
# snapshot_retention: 90d
#
# ── Retention tiers ────────────────────────────────────────────────
#
# default_retention_tier: critical
#
# snapshot_retention_tiers:
#   critical:
#     older_than: 30d
#     keep_min: 2
#   non_critical:
#     older_than: 14d
#     keep_min: 2
#
# ── Observation-to-tier mapping ────────────────────────────────────
#
# Map observation source_type values to retention tiers.
#
# observation_tier_mapping:
#   aws-s3-snapshot: critical
#   aws-iam-snapshot: critical
#
# ── CI integration ─────────────────────────────────────────────────
#
# ci_failure_policy controls when stave ci gate exits non-zero.
# Values: fail_on_any_violation, fail_on_new_violation, warn_only
#
# ci_failure_policy: fail_on_new_violation
#
# ── Capture cadence ────────────────────────────────────────────────
#
# How often snapshots are captured: daily or hourly.
#
# capture_cadence: daily
#
# ── Snapshot filename template ─────────────────────────────────────
#
# Naming pattern for observation files under observations/.
#
# snapshot_filename_template: YYYY-MM-DDT00:00:00Z.json
#
# ── Control packs ──────────────────────────────────────────────────
#
# Which built-in control packs to evaluate. Run stave controls list.
#
# enabled_control_packs:
#   - s3
#
# ── Exclude specific controls ─────────────────────────────────────
#
# Skip individual control IDs from evaluation.
#
# exclude_controls:
#   - CTL.S3.PUBLIC.901
#
# ── Suppressions ───────────────────────────────────────────────────
#
# Suppress known findings by asset + control. Useful for
# accepted risks or resources with compensating controls.
#
# suppressions:
#   - asset_id: "aws:s3:::legacy-public-assets"
#     control_id: CTL.S3.PUBLIC.001
#     reason: "Public assets bucket — accepted risk per SEC-2024-042"
#     expires: "2026-06-01"
`

const templateControlCanonical = `
dsl_version: ` + string(kernel.SchemaControl) + `
id: CTL.S3.PUBLIC.901
name: PHI buckets must not be public
description: Buckets with PHI must not be publicly readable or listable.
type: unsafe_state
params: {}
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
    - field: properties.storage.visibility.public_list
      op: eq
      value: true
    - field: properties.storage.visibility.public_write
      op: eq
      value: true
remediation:
  description: Bucket exposure exceeds safe default posture.
  action: Remove public read/list/write and re-capture a snapshot to confirm.
`

const templateObservation = `
{
  "schema_version": "` + string(kernel.SchemaObservation) + `",
  "generated_by": {
    "source_type": "aws-s3-snapshot",
    "tool": "stave-template"
  },
  "captured_at": "2026-01-11T00:00:00Z",
  "resources": [
    {
      "id": "aws:s3:::example-phi-bucket",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "visibility": {
            "public_read": false,
            "public_list": false
          }
        }
      }
    }
  ]
}
`
