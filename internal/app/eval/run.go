package eval

import (
	"context"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

// EvaluateRunner executes an evaluation run.
type EvaluateRunner interface {
	Execute(ctx context.Context, cfg EvaluateConfig) (evaluation.SafetyStatus, error)
}

type RunInput struct {
	Runner EvaluateRunner
	Config EvaluateConfig
}
