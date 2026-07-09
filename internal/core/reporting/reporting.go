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
