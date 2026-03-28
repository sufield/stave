package initcmd

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/env"
)

//go:embed templates/gitignore.txt
var gitignoreContent string

//go:embed templates/README.md.tmpl
var readmeTemplateSrc string

//go:embed templates/cli.yaml.tmpl
var userConfigTemplateSrc string

//go:embed templates/stave.lock.tmpl
var lockfileTemplateSrc string

// ScaffoldData holds all variables needed to render project templates.
type ScaffoldData struct {
	Version           string
	CaptureCadence    string
	SnapshotTemplate  string
	SnapshotExample   string
	ObsConvertCmd     string
	ProjectConfigFile string
	UserConfigEnv     string
	MaxUnsafeDuration string
	Retention         string
	RetentionTier     string
	CIFailurePolicy   string
}

// Scaffolder renders project scaffold templates using a populated ScaffoldData model.
type Scaffolder struct {
	Data ScaffoldData
}

// NewScaffolder creates a Scaffolder from scaffold options.
func NewScaffolder(opts scaffoldOptions) *Scaffolder {
	obsCmd := "Place observation JSON files in ./observations (see 'stave explain' for required fields)"
	if opts.Profile == profileAWSS3 {
		obsCmd = "Create observation JSON files in ./observations from your AWS S3 environment data"
	}
	return &Scaffolder{
		Data: ScaffoldData{
			Version:           Version(),
			CaptureCadence:    opts.CaptureCadence,
			SnapshotTemplate:  snapshotFilenameTemplate(opts.CaptureCadence),
			SnapshotExample:   snapshotFilenameExample(opts.CaptureCadence),
			ObsConvertCmd:     obsCmd,
			ProjectConfigFile: projectConfigFile,
			UserConfigEnv:     env.UserConfig.Name,
			MaxUnsafeDuration: defaultMaxUnsafeDuration,
			Retention:         defaultSnapshotRetention,
			RetentionTier:     defaultRetentionTier,
			CIFailurePolicy:   defaultCIFailurePolicy,
		},
	}
}

// Readme renders the project README from the embedded template.
func (s *Scaffolder) Readme() (string, error) {
	return renderTemplate(readmeTemplateSrc, "readme", s.Data)
}

// UserConfig renders the example CLI config from the embedded template.
func (s *Scaffolder) UserConfig() (string, error) {
	return renderTemplate(userConfigTemplateSrc, "userconfig", s.Data)
}

// Lockfile renders the stave.lock from the embedded template.
func (s *Scaffolder) Lockfile() (string, error) {
	return renderTemplate(lockfileTemplateSrc, "lockfile", s.Data)
}

func renderTemplate(src, name string, data ScaffoldData) (string, error) {
	tmpl, err := template.New(name).Parse(src)
	if err != nil {
		return "", fmt.Errorf("parse %s template: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute %s template: %w", name, err)
	}
	return buf.String(), nil
}

// --- Static template constants (use compile-time kernel.Schema* values) ---

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
# ── Predicate (when is the asset unsafe?) ───────────────────────
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

const templateObservationSample = `{
  "schema_version": "` + string(kernel.SchemaObservation) + `",
  "generated_by": {
    "source_type": "aws-s3-snapshot",
    "tool": "stave-template"
  },
  "captured_at": "2026-01-11T00:00:00Z",
  "assets": [
    {
      "id": "aws:s3:::example-phi-bucket",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "access": {
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
# How long an asset can remain in an unsafe state before Stave
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
# snapshot_filename_template: YYYY-MM-DDT000000Z.json
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
# ── Exceptions ───────────────────────────────────────────────────
#
# Suppress known findings by asset + control. Useful for
# accepted risks or resources with compensating controls.
#
# exceptions:
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
    - field: properties.storage.access.public_read
      op: eq
      value: true
    - field: properties.storage.access.public_list
      op: eq
      value: true
    - field: properties.storage.access.public_write
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
  "assets": [
    {
      "id": "aws:s3:::example-phi-bucket",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "access": {
            "public_read": false,
            "public_list": false
          }
        }
      }
    }
  ]
}
`
