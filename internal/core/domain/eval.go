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
