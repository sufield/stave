package reporting

import "time"

// --- Baseline ---

type BaselineSaveRequest struct {
	EvaluationPath string     `json:"evaluation_path"`
	OutputPath     string     `json:"output_path"`
	Now            *time.Time `json:"now,omitempty"`
	Sanitize       bool       `json:"sanitize,omitempty"`
	Force          bool       `json:"force,omitempty"`
}

type BaselineSaveResponse struct {
	OutputPath    string    `json:"output_path"`
	FindingsCount int       `json:"findings_count"`
	CreatedAt     time.Time `json:"created_at"`
}

type BaselineCheckRequest struct {
	EvaluationPath string `json:"evaluation_path"`
	BaselinePath   string `json:"baseline_path"`
	FailOnNew      bool   `json:"fail_on_new"`
	Sanitize       bool   `json:"sanitize,omitempty"`
}

type BaselineCheckResponse struct {
	BaselineFile     string               `json:"baseline_file"`
	Evaluation       string               `json:"evaluation"`
	CheckedAt        time.Time            `json:"checked_at"`
	Summary          BaselineCheckSummary `json:"summary"`
	NewFindings      []BaselineFinding    `json:"new"`
	ResolvedFindings []BaselineFinding    `json:"resolved"`
	HasNew           bool                 `json:"has_new"`
}

type BaselineCheckSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

type BaselineFinding struct {
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
	AssetID     string `json:"asset_id"`
	AssetType   string `json:"asset_type"`
}
