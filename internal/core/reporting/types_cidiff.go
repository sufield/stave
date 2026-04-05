package reporting

import "time"

// --- CI Diff ---

type CIDiffRequest struct {
	CurrentPath  string `json:"current_path"`
	BaselinePath string `json:"baseline_path"`
	FailOnNew    bool   `json:"fail_on_new"`
	Sanitize     bool   `json:"sanitize,omitempty"`
}

type CIDiffResponse struct {
	CurrentEvaluation  string            `json:"current_evaluation"`
	BaselineEvaluation string            `json:"baseline_evaluation"`
	ComparedAt         time.Time         `json:"compared_at"`
	Summary            CIDiffSummary     `json:"summary"`
	NewFindings        []BaselineFinding `json:"new"`
	ResolvedFindings   []BaselineFinding `json:"resolved"`
	HasNew             bool              `json:"has_new"`
}

type CIDiffSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}
