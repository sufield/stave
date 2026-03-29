// Package eval provides request/response types and use case orchestration
// for the control evaluation pipeline: apply, fix, fix-loop, gate, trace,
// and verify. The gate use case implements CI failure policies with
// configurable strategies (fail-on-any, fail-on-new, fail-on-overdue).
package eval

import "time"

// --- Gate ---

type GateRequest struct {
	Policy            string        `json:"policy"`
	EvaluationPath    string        `json:"evaluation_path,omitempty"`
	BaselinePath      string        `json:"baseline_path,omitempty"`
	ControlsDir       string        `json:"controls_dir,omitempty"`
	ObservationsDir   string        `json:"observations_dir,omitempty"`
	MaxUnsafeDuration time.Duration `json:"max_unsafe_duration,omitempty"`
	Now               *time.Time    `json:"now,omitempty"`
}

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

type FixRequest struct {
	InputPath  string `json:"input_path"`
	FindingRef string `json:"finding_ref"`
}

type FixResponse struct {
	Data any `json:"data"`
}

// --- Trace ---

type TraceRequest struct {
	ControlID       string `json:"control_id"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationPath string `json:"observation_path"`
	AssetID         string `json:"asset_id"`
}

type TraceResponse struct {
	TraceData any `json:"trace_data"`
}

// --- Apply ---

type ApplyRequest struct {
	ControlsDir        string   `json:"controls_dir,omitempty"`
	ObservationsDir    string   `json:"observations_dir,omitempty"`
	MaxUnsafeDuration  string   `json:"max_unsafe_duration,omitempty"`
	NowTime            string   `json:"now_time,omitempty"`
	Format             string   `json:"format,omitempty"`
	DryRun             bool     `json:"dry_run,omitempty"`
	AllowUnknownInput  bool     `json:"allow_unknown_input,omitempty"`
	ExemptionFile      string   `json:"exemption_file,omitempty"`
	IntegrityManifest  string   `json:"integrity_manifest,omitempty"`
	IntegrityPublicKey string   `json:"integrity_public_key,omitempty"`
	Profile            string   `json:"profile,omitempty"`
	InputFile          string   `json:"input_file,omitempty"`
	BucketAllowlist    []string `json:"bucket_allowlist,omitempty"`
	IncludeAll         bool     `json:"include_all,omitempty"`
}

type ApplyResponse struct {
	EvaluationData any      `json:"evaluation_data"`
	HasViolations  bool     `json:"has_violations"`
	Warnings       []string `json:"warnings,omitempty"`
}

// --- Verify ---

type VerifyRequest struct {
	BeforeDir         string `json:"before_dir"`
	AfterDir          string `json:"after_dir"`
	ControlsDir       string `json:"controls_dir,omitempty"`
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`
	NowTime           string `json:"now_time,omitempty"`
	AllowUnknownInput bool   `json:"allow_unknown_input,omitempty"`
}

type VerifyResponse struct {
	VerificationData any  `json:"verification_data"`
	HasRemaining     bool `json:"has_remaining"`
	HasIntroduced    bool `json:"has_introduced"`
}

// --- Fix Loop ---

type FixLoopRequest struct {
	BeforeDir         string `json:"before_dir"`
	AfterDir          string `json:"after_dir"`
	ControlsDir       string `json:"controls_dir,omitempty"`
	OutDir            string `json:"out_dir,omitempty"`
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`
	NowTime           string `json:"now_time,omitempty"`
	AllowUnknownInput bool   `json:"allow_unknown_input,omitempty"`
}

type FixLoopResponse struct {
	ReportData    any  `json:"report_data"`
	HasViolations bool `json:"has_violations"`
}
