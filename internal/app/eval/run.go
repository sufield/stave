package eval

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/domain/evaluation"
)

// EvaluateRunner executes an evaluation run.
type EvaluateRunner interface {
	Execute(ctx context.Context, cfg EvaluateConfig) (evaluation.SafetyStatus, error)
}

type RunInput struct {
	Runner EvaluateRunner
	Config EvaluateConfig
}

func Run(ctx context.Context, in RunInput) (evaluation.SafetyStatus, error) {
	status, err := in.Runner.Execute(ctx, in.Config)
	if err != nil {
		return "", fmt.Errorf("evaluation runner: %w", err)
	}
	return status, nil
}
