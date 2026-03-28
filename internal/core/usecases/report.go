package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// ReportEvaluationLoaderPort loads an evaluation artifact for reporting.
type ReportEvaluationLoaderPort interface {
	LoadEvaluation(ctx context.Context, path string) (any, error)
}

// ReportDeps groups the port interfaces for the report use case.
type ReportDeps struct {
	Loader ReportEvaluationLoaderPort
}

// Report loads an evaluation artifact and returns it for rendering.
func Report(
	ctx context.Context,
	req domain.ReportRequest,
	deps ReportDeps,
) (domain.ReportResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReportResponse{}, fmt.Errorf("report: %w", err)
	}

	eval, err := deps.Loader.LoadEvaluation(ctx, req.InputFile)
	if err != nil {
		return domain.ReportResponse{}, fmt.Errorf("report: load evaluation %s: %w", req.InputFile, err)
	}

	return domain.ReportResponse{EvaluationData: eval}, nil
}
