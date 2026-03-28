package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// EvaluationRunnerPort runs control evaluation against observations.
type EvaluationRunnerPort interface {
	RunEvaluation(ctx context.Context, req domain.ApplyRequest) (domain.ApplyResponse, error)
}

// ApplyDeps groups the port interfaces for the apply use case.
type ApplyDeps struct {
	Runner EvaluationRunnerPort
}

// Apply runs control evaluation after validating inputs.
func Apply(
	ctx context.Context,
	req domain.ApplyRequest,
	deps ApplyDeps,
) (domain.ApplyResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.ApplyResponse{}, fmt.Errorf("apply: %w", err)
	}

	if req.Profile != "" && req.InputFile == "" {
		return domain.ApplyResponse{}, fmt.Errorf("apply: --input is required when using --profile")
	}

	resp, err := deps.Runner.RunEvaluation(ctx, req)
	if err != nil {
		return domain.ApplyResponse{}, fmt.Errorf("apply: %w", err)
	}

	return resp, nil
}
