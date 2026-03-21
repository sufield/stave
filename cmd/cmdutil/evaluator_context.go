package cmdutil

import (
	"context"

	"github.com/spf13/cobra"

	appconfig "github.com/sufield/stave/internal/app/config"
)

type evaluatorKey struct{}

// WithEvaluator returns a context carrying the resolved project config evaluator.
// Call this once during bootstrap; commands retrieve it via EvaluatorFromCmd.
func WithEvaluator(ctx context.Context, eval *appconfig.Evaluator) context.Context {
	return context.WithValue(ctx, evaluatorKey{}, eval)
}

// EvaluatorFromCmd retrieves the project config evaluator from the command's context.
// Returns nil if the evaluator was not set (e.g., for tolerant commands like init/help).
func EvaluatorFromCmd(cmd *cobra.Command) *appconfig.Evaluator {
	if cmd == nil {
		return nil
	}
	eval, _ := cmd.Context().Value(evaluatorKey{}).(*appconfig.Evaluator)
	return eval
}
