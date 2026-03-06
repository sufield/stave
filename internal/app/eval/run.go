package eval

import (
	"context"
	"fmt"

	appworkflow "github.com/sufield/stave/internal/app/workflow"
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

func Run(ctx context.Context, in RunInput) (appworkflow.EvaluateResult, error) {
	status, err := in.Runner.Execute(ctx, in.Config)
	if err != nil {
		return appworkflow.EvaluateResult{}, fmt.Errorf("evaluation runner: %w", err)
	}
	return appworkflow.BuildEvaluateResult(status, in.Config.ControlsDir, in.Config.ObservationsDir), nil
}
