package reporting

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/report"
)

// --- Report ---

// ReportEvaluationLoaderPort loads an evaluation artifact for reporting.
type ReportEvaluationLoaderPort interface {
	LoadEvaluation(ctx context.Context, path string) (*report.Assessment, error)
}

// ReportDeps represents a reportdeps value.
type ReportDeps struct {
	Loader ReportEvaluationLoaderPort
}

// Report loads an evaluation artifact for rendering.
func Report(ctx context.Context, req ReportRequest, deps ReportDeps) (ReportResponse, error) {
	if err := ctx.Err(); err != nil {
		return ReportResponse{}, fmt.Errorf("report: %w", err)
	}
	data, err := deps.Loader.LoadEvaluation(ctx, req.InputFile)
	if err != nil {
		return ReportResponse{}, fmt.Errorf("report: %w", err)
	}
	return ReportResponse{EvaluationData: data}, nil
}

// --- Enforce ---

// EnforceTemplateGeneratorPort generates enforcement templates from evaluation output.
type EnforceTemplateGeneratorPort interface {
	GenerateTemplate(ctx context.Context, req EnforceRequest) (EnforceResponse, error)
}

// EnforceDeps represents a enforcedeps value.
type EnforceDeps struct {
	Generator EnforceTemplateGeneratorPort
}

// Enforce generates enforcement templates from evaluation output.
func Enforce(ctx context.Context, req EnforceRequest, deps EnforceDeps) (EnforceResponse, error) {
	if err := ctx.Err(); err != nil {
		return EnforceResponse{}, fmt.Errorf("enforce: %w", err)
	}
	resp, err := deps.Generator.GenerateTemplate(ctx, req)
	if err != nil {
		return EnforceResponse{}, fmt.Errorf("enforce: %w", err)
	}
	return resp, nil
}

// --- Prompt From Finding ---

// PromptGeneratorPort generates an LLM prompt from evaluation findings.
type PromptGeneratorPort interface {
	GeneratePrompt(ctx context.Context, req PromptFromFindingRequest) (PromptFromFindingResponse, error)
}

// PromptFromFindingDeps represents a promptfromfindingdeps value.
type PromptFromFindingDeps struct {
	Generator PromptGeneratorPort
}

// PromptFromFinding generates an LLM prompt from evaluation findings for a specific asset.
func PromptFromFinding(ctx context.Context, req PromptFromFindingRequest, deps PromptFromFindingDeps) (PromptFromFindingResponse, error) {
	if err := ctx.Err(); err != nil {
		return PromptFromFindingResponse{}, fmt.Errorf("prompt-from-finding: %w", err)
	}
	if req.EvaluationFile == "" {
		return PromptFromFindingResponse{}, fmt.Errorf("prompt-from-finding: evaluation file is required")
	}
	if req.AssetID == "" {
		return PromptFromFindingResponse{}, fmt.Errorf("prompt-from-finding: asset ID is required")
	}
	resp, err := deps.Generator.GeneratePrompt(ctx, req)
	if err != nil {
		return PromptFromFindingResponse{}, fmt.Errorf("prompt-from-finding: %w", err)
	}
	return resp, nil
}

// --- Prompt Types ---

// PromptFromFindingRequest represents a promptfromfindingrequest value.
type PromptFromFindingRequest struct {
	EvaluationFile  string `json:"evaluation_file"`
	AssetID         string `json:"asset_id"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationsDir string `json:"observations_dir,omitempty"`
}

// PromptFromFindingResponse represents a promptfromfindingresponse value.
type PromptFromFindingResponse struct {
	Rendered   string   `json:"rendered"`
	FindingIDs []string `json:"finding_ids"`
	AssetID    string   `json:"asset_id"`
}

// --- Report Types ---

// ReportRequest represents a reportrequest value.
type ReportRequest struct {
	InputFile    string `json:"input_file"`
	TemplateFile string `json:"template_file,omitempty"`
	Format       string `json:"format,omitempty"`
	Quiet        bool   `json:"quiet,omitempty"`
}

// ReportResponse represents a reportresponse value.
type ReportResponse struct {
	EvaluationData *report.Assessment `json:"evaluation_data"`
}

// --- CI Diff Types ---

// CIDiffRequest represents a cidiffrequest value.
type CIDiffRequest struct {
	CurrentPath  string `json:"current_path"`
	BaselinePath string `json:"baseline_path"`
	FailOnNew    bool   `json:"fail_on_new"`
	Sanitize     bool   `json:"sanitize,omitempty"`
}

// CIDiffResponse represents a cidiffresponse value.
type CIDiffResponse struct {
	CurrentEvaluation  string            `json:"current_evaluation"`
	BaselineEvaluation string            `json:"baseline_evaluation"`
	ComparedAt         time.Time         `json:"compared_at"`
	Summary            CIDiffSummary     `json:"summary"`
	NewFindings        []BaselineFinding `json:"new"`
	ResolvedFindings   []BaselineFinding `json:"resolved"`
	HasNew             bool              `json:"has_new"`
}

// CIDiffSummary represents a cidiffsummary value.
type CIDiffSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

// --- Enforce Types ---

// EnforceRequest represents a enforcerequest value.
type EnforceRequest struct {
	InputPath string `json:"input_path"`
	OutDir    string `json:"out_dir,omitempty"`
	Mode      string `json:"mode"`
	DryRun    bool   `json:"dry_run,omitempty"`
}

// EnforceResponse represents a enforceresponse value.
type EnforceResponse struct {
	OutputFile string   `json:"output_file"`
	Targets    []string `json:"targets"`
	DryRun     bool     `json:"dry_run,omitempty"`
}
