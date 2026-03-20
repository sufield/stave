package eval

import (
	"context"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

// Run executes the evaluation workflow: delegates to the runner and returns the status.
func Run(ctx context.Context, input RunInput) (evaluation.SafetyStatus, error) {
	return input.Runner.Execute(ctx, input.Config)
}
