package reporting

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/safetyenvelope"
)

// --- Report ---

// ReportEvaluationLoaderPort loads an evaluation artifact for reporting.
type ReportEvaluationLoaderPort interface {
	LoadEvaluation(ctx context.Context, path string) (*safetyenvelope.Evaluation, error)
}

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
