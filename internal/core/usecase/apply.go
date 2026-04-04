package usecase

import (
	"context"
	"fmt"
)

// EvaluationRunnerPort runs control evaluation against observations.
type EvaluationRunnerPort interface {
	RunEvaluation(ctx context.Context, req ApplyRequest) (ApplyResponse, error)
}

// ApplyDeps groups the port interfaces for the apply use case.
type ApplyDeps struct {
	Runner EvaluationRunnerPort
}

// Apply runs control evaluation after validating inputs.
func Apply(ctx context.Context, req ApplyRequest, deps ApplyDeps) (ApplyResponse, error) {
	if err := ctx.Err(); err != nil {
		return ApplyResponse{}, fmt.Errorf("apply: %w", err)
	}

	if req.Profile != "" && req.InputFile == "" {
		return ApplyResponse{}, fmt.Errorf("apply: --input is required when using --profile")
	}

	resp, err := deps.Runner.RunEvaluation(ctx, req)
	if err != nil {
		return ApplyResponse{}, fmt.Errorf("apply: %w", err)
	}

	return resp, nil
}
