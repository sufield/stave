package usecases

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/domain"
)

// CIDiffEvaluationLoaderPort loads evaluation findings from a file.
type CIDiffEvaluationLoaderPort interface {
	LoadFindings(ctx context.Context, path string) ([]domain.BaselineFinding, error)
}

// CIDiffDeps groups the port interfaces for the CI diff use case.
type CIDiffDeps struct {
	CurrentLoader  CIDiffEvaluationLoaderPort
	BaselineLoader CIDiffEvaluationLoaderPort
	Clock          func() time.Time
}

// CIDiff compares two evaluation artifacts and identifies new and resolved findings.
func CIDiff(
	ctx context.Context,
	req domain.CIDiffRequest,
	deps CIDiffDeps,
) (domain.CIDiffResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.CIDiffResponse{}, fmt.Errorf("ci_diff: %w", err)
	}

	current, err := deps.CurrentLoader.LoadFindings(ctx, req.CurrentPath)
	if err != nil {
		return domain.CIDiffResponse{}, fmt.Errorf("ci_diff: load current %s: %w", req.CurrentPath, err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain.CIDiffResponse{}, fmt.Errorf("ci_diff: %w", ctxErr)
	}

	baseline, err := deps.BaselineLoader.LoadFindings(ctx, req.BaselinePath)
	if err != nil {
		return domain.CIDiffResponse{}, fmt.Errorf("ci_diff: load baseline %s: %w", req.BaselinePath, err)
	}

	newFindings, resolved := compareFindings(baseline, current)
	hasNew := len(newFindings) > 0

	return domain.CIDiffResponse{
		CurrentEvaluation:  req.CurrentPath,
		BaselineEvaluation: req.BaselinePath,
		ComparedAt:         deps.Clock().UTC(),
		Summary: domain.CIDiffSummary{
			BaselineFindings: len(baseline),
			CurrentFindings:  len(current),
			NewFindings:      len(newFindings),
			ResolvedFindings: len(resolved),
		},
		NewFindings:      newFindings,
		ResolvedFindings: resolved,
		HasNew:           hasNew,
	}, nil
}
