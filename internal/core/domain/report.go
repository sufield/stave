package domain

import "time"

// --- Baseline Save ---

// BaselineSaveRequest defines the inputs for capturing current evaluation
// findings as a baseline snapshot.
type BaselineSaveRequest struct {
	// EvaluationPath is the path to the evaluation JSON file.
	// CLI flag: --in (required)
	EvaluationPath string `json:"evaluation_path"`

	// OutputPath is the destination path for the baseline JSON file.
	// CLI flag: --out (default: "output/baseline.json")
	OutputPath string `json:"output_path"`

	// Now overrides the current time for deterministic output.
	// CLI flag: --now (optional, RFC3339)
	Now *time.Time `json:"now,omitempty"`

	// Sanitize controls whether asset identifiers are pseudonymized.
	// CLI flag: --sanitize
	Sanitize bool `json:"sanitize,omitempty"`

	// Force allows overwriting an existing baseline file.
	// CLI flag: --force
	Force bool `json:"force,omitempty"`
}

// BaselineSaveResponse contains the result of saving a baseline snapshot.
type BaselineSaveResponse struct {
	// OutputPath is the path where the baseline file was written.
	OutputPath string `json:"output_path"`

	// FindingsCount is the number of findings captured in the baseline.
	FindingsCount int `json:"findings_count"`

	// CreatedAt is the timestamp recorded in the baseline.
	CreatedAt time.Time `json:"created_at"`
}

// --- Baseline Check ---

// BaselineCheckRequest defines the inputs for comparing current evaluation
// findings against a saved baseline.
type BaselineCheckRequest struct {
	// EvaluationPath is the path to the current evaluation JSON file.
	// CLI flag: --in (required)
	EvaluationPath string `json:"evaluation_path"`

	// BaselinePath is the path to the saved baseline JSON file.
	// CLI flag: --baseline (required)
	BaselinePath string `json:"baseline_path"`

	// FailOnNew controls whether new findings cause a non-zero exit code.
	// CLI flag: --fail-on-new (default: true)
	FailOnNew bool `json:"fail_on_new"`

	// Sanitize controls whether asset identifiers are pseudonymized.
	// CLI flag: --sanitize
	Sanitize bool `json:"sanitize,omitempty"`
}

// BaselineCheckResponse contains the result of comparing findings against a baseline.
type BaselineCheckResponse struct {
	BaselineFile     string               `json:"baseline_file"`
	Evaluation       string               `json:"evaluation"`
	CheckedAt        time.Time            `json:"checked_at"`
	Summary          BaselineCheckSummary `json:"summary"`
	NewFindings      []BaselineFinding    `json:"new"`
	ResolvedFindings []BaselineFinding    `json:"resolved"`
	HasNew           bool                 `json:"has_new"`
}

// BaselineCheckSummary provides aggregate counts for a baseline comparison.
type BaselineCheckSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

// BaselineFinding identifies a single finding by its control and asset.
type BaselineFinding struct {
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
	AssetID     string `json:"asset_id"`
	AssetType   string `json:"asset_type"`
}

// --- CI Diff ---

// CIDiffRequest defines the inputs for comparing two evaluation artifacts
// and reporting new and resolved findings.
type CIDiffRequest struct {
	// CurrentPath is the path to the current evaluation JSON file.
	// CLI flag: --current (required)
	CurrentPath string `json:"current_path"`

	// BaselinePath is the path to the baseline evaluation JSON file.
	// CLI flag: --baseline (required)
	BaselinePath string `json:"baseline_path"`

	// FailOnNew controls whether new findings cause a non-zero exit code.
	// CLI flag: --fail-on-new (default: true)
	FailOnNew bool `json:"fail_on_new"`

	// Sanitize controls whether asset identifiers are pseudonymized.
	// CLI flag: --sanitize
	Sanitize bool `json:"sanitize,omitempty"`
}

// CIDiffResponse contains the result of comparing two evaluation artifacts.
type CIDiffResponse struct {
	CurrentEvaluation  string            `json:"current_evaluation"`
	BaselineEvaluation string            `json:"baseline_evaluation"`
	ComparedAt         time.Time         `json:"compared_at"`
	Summary            CIDiffSummary     `json:"summary"`
	NewFindings        []BaselineFinding `json:"new"`
	ResolvedFindings   []BaselineFinding `json:"resolved"`
	HasNew             bool              `json:"has_new"`
}

// CIDiffSummary provides aggregate counts for a CI diff comparison.
type CIDiffSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

// --- Report ---

// ReportRequest defines the inputs for generating a report from evaluation output.
type ReportRequest struct {
	InputFile    string `json:"input_file"`
	TemplateFile string `json:"template_file,omitempty"`
	Format       string `json:"format,omitempty"`
	Quiet        bool   `json:"quiet,omitempty"`
}

// ReportResponse contains the loaded evaluation data for rendering.
type ReportResponse struct {
	EvaluationData any `json:"evaluation_data"`
}

// --- Explain ---

// ExplainRequest defines the inputs for explaining a control's evaluation logic.
type ExplainRequest struct {
	// ControlID is the identifier of the control to explain.
	// CLI arg: <control-id> (required, positional)
	ControlID string `json:"control_id"`

	// ControlsDir is the path to control definitions directory.
	// CLI flag: --controls (default from config)
	ControlsDir string `json:"controls_dir,omitempty"`
}

// ExplainResponse contains the breakdown of a control's predicate rules.
type ExplainResponse struct {
	// ControlID is the control that was explained.
	ControlID string `json:"control_id"`

	// Name is the control's human-readable name.
	Name string `json:"name"`

	// Description is the control's description.
	Description string `json:"description,omitempty"`

	// Type is the control type (e.g. unsafe_state, unsafe_duration).
	Type string `json:"type,omitempty"`

	// MatchedFields are the field paths referenced by the predicate.
	MatchedFields []string `json:"matched_fields,omitempty"`

	// Rules are the individual predicate rules.
	Rules []ExplainRule `json:"rules,omitempty"`

	// MinimalObservation is a sample obs.v0.1 JSON snippet.
	MinimalObservation any `json:"minimal_observation,omitempty"`
}

// ExplainRule represents a single predicate rule within a control.
type ExplainRule struct {
	Path    string `json:"path"`
	Op      string `json:"op"`
	Value   any    `json:"value,omitempty"`
	From    string `json:"from,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// --- Diagnose ---

// DiagnoseRequest defines the inputs for running diagnostic analysis.
type DiagnoseRequest struct {
	// ControlsDir is the path to control definitions directory.
	// CLI flag: --controls
	ControlsDir string `json:"controls_dir,omitempty"`

	// ObservationsDir is the path to observation snapshots directory.
	// CLI flag: --observations
	ObservationsDir string `json:"observations_dir,omitempty"`

	// PreviousOutput is an optional path to existing apply output JSON.
	// CLI flag: --previous-output
	PreviousOutput string `json:"previous_output,omitempty"`

	// MaxUnsafeDuration is the threshold for unsafe duration.
	// CLI flag: --max-unsafe
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`

	// Now overrides the current time for deterministic output.
	// CLI flag: --now
	Now string `json:"now,omitempty"`

	// CaseFilter filters to specific diagnostic cases.
	// CLI flag: --case (repeatable)
	CaseFilter []string `json:"case_filter,omitempty"`

	// SignalContains filters diagnostics by signal substring.
	// CLI flag: --signal-contains
	SignalContains string `json:"signal_contains,omitempty"`

	// ControlID is for single-finding detail mode.
	// CLI flag: --control-id
	ControlID string `json:"control_id,omitempty"`

	// AssetID is for single-finding detail mode.
	// CLI flag: --asset-id
	AssetID string `json:"asset_id,omitempty"`
}

// DiagnoseResponse contains the diagnostic analysis results.
type DiagnoseResponse struct {
	// ReportData holds the diagnostic report, ready for rendering.
	ReportData any `json:"report_data"`

	// IsDetailMode indicates whether this is a single-finding detail response.
	IsDetailMode bool `json:"is_detail_mode,omitempty"`
}

// --- Enforce (Generate Templates) ---

// EnforceRequest defines the inputs for generating enforcement templates.
type EnforceRequest struct {
	// InputPath is the path to evaluation JSON.
	// CLI flag: --in (required)
	InputPath string `json:"input_path"`

	// OutDir is the output directory for generated templates.
	// CLI flag: --out (default: "output")
	OutDir string `json:"out_dir,omitempty"`

	// Mode is the enforcement mode: pab or scp.
	// CLI flag: --mode (default: pab)
	Mode string `json:"mode"`

	// DryRun previews planned paths without writing files.
	// CLI flag: --dry-run
	DryRun bool `json:"dry_run,omitempty"`
}

// EnforceResponse contains the result of generating enforcement templates.
type EnforceResponse struct {
	// OutputFile is the path where the template was (or would be) written.
	OutputFile string `json:"output_file"`

	// Targets are the bucket/resource names targeted by the template.
	Targets []string `json:"targets"`

	// DryRun indicates this was a preview only.
	DryRun bool `json:"dry_run,omitempty"`
}
