// Package reporting provides domain types and use cases for evaluation
// reporting: baseline save/check, CI diff, diagnose, enforce template
// generation, documentation search/open, prompt generation, and report loading.
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

// --- Report ---

type ReportRequest struct {
	InputFile    string `json:"input_file"`
	TemplateFile string `json:"template_file,omitempty"`
	Format       string `json:"format,omitempty"`
	Quiet        bool   `json:"quiet,omitempty"`
}

type ReportResponse struct {
	EvaluationData any `json:"evaluation_data"`
}

// --- Diagnose ---

type DiagnoseRequest struct {
	ControlsDir       string   `json:"controls_dir,omitempty"`
	ObservationsDir   string   `json:"observations_dir,omitempty"`
	PreviousOutput    string   `json:"previous_output,omitempty"`
	MaxUnsafeDuration string   `json:"max_unsafe_duration,omitempty"`
	Now               string   `json:"now,omitempty"`
	CaseFilter        []string `json:"case_filter,omitempty"`
	SignalContains    string   `json:"signal_contains,omitempty"`
	ControlID         string   `json:"control_id,omitempty"`
	AssetID           string   `json:"asset_id,omitempty"`
}

type DiagnoseResponse struct {
	ReportData   any  `json:"report_data"`
	IsDetailMode bool `json:"is_detail_mode,omitempty"`
}

// --- Enforce ---

type EnforceRequest struct {
	InputPath string `json:"input_path"`
	OutDir    string `json:"out_dir,omitempty"`
	Mode      string `json:"mode"`
	DryRun    bool   `json:"dry_run,omitempty"`
}

type EnforceResponse struct {
	OutputFile string   `json:"output_file"`
	Targets    []string `json:"targets"`
	DryRun     bool     `json:"dry_run,omitempty"`
}

// --- Docs Search ---

type DocsSearchRequest struct {
	Query         string   `json:"query"`
	Root          string   `json:"root,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	MaxResults    int      `json:"max_results"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
}

type DocsSearchHit struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Score   int    `json:"score"`
	Snippet string `json:"snippet"`
}

type DocsSearchResponse struct {
	Query    string          `json:"query"`
	Total    int             `json:"total"`
	Returned int             `json:"returned"`
	Hits     []DocsSearchHit `json:"hits"`
}

// --- Docs Open ---

type DocsOpenRequest struct {
	Topic string   `json:"topic"`
	Root  string   `json:"root,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

type DocsOpenResponse struct {
	Topic   string `json:"topic"`
	Path    string `json:"path"`
	Match   string `json:"match"`
	Summary string `json:"summary"`
}

// --- Prompt From Finding ---

type PromptFromFindingRequest struct {
	EvaluationFile  string `json:"evaluation_file"`
	AssetID         string `json:"asset_id"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationsDir string `json:"observations_dir,omitempty"`
}

type PromptFromFindingResponse struct {
	Rendered   string   `json:"rendered"`
	FindingIDs []string `json:"finding_ids"`
	AssetID    string   `json:"asset_id"`
}
