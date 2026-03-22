package cmdutil

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"

	appconfig "github.com/sufield/stave/internal/app/config"
)

type evaluatorKey struct{}
type loggerKey struct{}

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

// WithLogger returns a context carrying the configured logger.
// Call this once during bootstrap; commands retrieve it via LoggerFromCmd.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// LoggerFromCmd retrieves the configured logger from the command's context.
// Falls back to slog.Default() if no logger was stored (e.g., in tests).
func LoggerFromCmd(cmd *cobra.Command) *slog.Logger {
	if cmd != nil {
		if l, ok := cmd.Context().Value(loggerKey{}).(*slog.Logger); ok && l != nil {
			return l
		}
	}
	return slog.Default()
}
