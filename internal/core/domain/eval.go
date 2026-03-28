package domain

import "time"

// --- Gate ---

// GateRequest defines the inputs for enforcing a CI failure policy.
type GateRequest struct {
	Policy            string        `json:"policy"`
	EvaluationPath    string        `json:"evaluation_path,omitempty"`
	BaselinePath      string        `json:"baseline_path,omitempty"`
	ControlsDir       string        `json:"controls_dir,omitempty"`
	ObservationsDir   string        `json:"observations_dir,omitempty"`
	MaxUnsafeDuration time.Duration `json:"max_unsafe_duration,omitempty"`
	Now               *time.Time    `json:"now,omitempty"`
}

// GateResponse contains the result of a CI gate policy evaluation.
type GateResponse struct {
	Policy            string    `json:"policy"`
	Passed            bool      `json:"pass"`
	Reason            string    `json:"reason"`
	CheckedAt         time.Time `json:"checked_at"`
	EvaluationPath    string    `json:"evaluation_path,omitempty"`
	BaselinePath      string    `json:"baseline_path,omitempty"`
	ControlsPath      string    `json:"controls_path,omitempty"`
	ObservationsPath  string    `json:"observations_path,omitempty"`
	CurrentViolations int       `json:"current_violations,omitempty"`
	NewViolations     int       `json:"new_violations,omitempty"`
	OverdueUpcoming   int       `json:"overdue_upcoming,omitempty"`
}

// --- Fix ---

// FixRequest defines the inputs for generating a remediation plan for a single finding.
type FixRequest struct {
	InputPath  string `json:"input_path"`
	FindingRef string `json:"finding_ref"`
}

// FixResponse contains the remediation guidance for a single finding.
type FixResponse struct {
	Data any `json:"data"`
}

// --- Trace ---

// TraceRequest defines the inputs for tracing predicate evaluation.
type TraceRequest struct {
	// ControlID is the control to trace.
	// CLI flag: --control (required)
	ControlID string `json:"control_id"`

	// ControlsDir is the path to control definitions directory.
	// CLI flag: --controls
	ControlsDir string `json:"controls_dir,omitempty"`

	// ObservationPath is the path to a single observation JSON file.
	// CLI flag: --observation (required)
	ObservationPath string `json:"observation_path"`

	// AssetID is the asset ID to trace against.
	// CLI flag: --asset-id (required)
	AssetID string `json:"asset_id"`
}

// TraceResponse contains the predicate evaluation trace.
type TraceResponse struct {
	// TraceData holds the evaluation trace, ready for rendering.
	TraceData any `json:"trace_data"`
}

// --- Apply ---

// ApplyRequest defines the inputs for running control evaluation.
type ApplyRequest struct {
	// ControlsDir is the path to control definitions directory.
	// CLI flag: --controls (default: controls)
	ControlsDir string `json:"controls_dir,omitempty"`

	// ObservationsDir is the path to observation snapshots directory.
	// CLI flag: --observations (default: observations)
	ObservationsDir string `json:"observations_dir,omitempty"`

	// MaxUnsafeDuration is the maximum allowed unsafe duration (e.g. "168h").
	// CLI flag: --max-unsafe
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`

	// NowTime overrides the current time (RFC3339) for deterministic output.
	// CLI flag: --now
	NowTime string `json:"now_time,omitempty"`

	// Format is the output format: json, text, or sarif.
	// CLI flag: --format (default: json)
	Format string `json:"format,omitempty"`

	// DryRun runs readiness checks only without evaluating controls.
	// CLI flag: --dry-run
	DryRun bool `json:"dry_run,omitempty"`

	// AllowUnknownInput allows observations with unknown source types.
	// CLI flag: --allow-unknown-input
	AllowUnknownInput bool `json:"allow_unknown_input,omitempty"`

	// ExemptionFile is the path to an asset exemption list YAML file.
	// CLI flag: --exemption-file
	ExemptionFile string `json:"exemption_file,omitempty"`

	// IntegrityManifest is the path to a manifest JSON with expected hashes.
	// CLI flag: --integrity-manifest
	IntegrityManifest string `json:"integrity_manifest,omitempty"`

	// IntegrityPublicKey is the path to an Ed25519 public key for signed manifests.
	// CLI flag: --integrity-public-key
	IntegrityPublicKey string `json:"integrity_public_key,omitempty"`

	// Profile is the evaluation profile (e.g. aws-s3).
	// CLI flag: --profile
	Profile string `json:"profile,omitempty"`

	// InputFile is the path to an observations bundle file (required with --profile).
	// CLI flag: --input
	InputFile string `json:"input_file,omitempty"`

	// BucketAllowlist limits evaluation to specific bucket names/ARNs.
	// CLI flag: --bucket-allowlist
	BucketAllowlist []string `json:"bucket_allowlist,omitempty"`

	// IncludeAll disables health scope filtering.
	// CLI flag: --include-all
	IncludeAll bool `json:"include_all,omitempty"`
}

// ApplyResponse contains the result of control evaluation.
type ApplyResponse struct {
	// EvaluationData holds the evaluation output, ready for rendering.
	EvaluationData any `json:"evaluation_data"`

	// HasViolations indicates whether any controls were violated.
	HasViolations bool `json:"has_violations"`

	// Warnings lists non-fatal issues encountered during evaluation.
	Warnings []string `json:"warnings,omitempty"`
}
