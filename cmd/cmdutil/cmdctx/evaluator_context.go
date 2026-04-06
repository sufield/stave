// Package cmdctx provides evaluation-level context propagation.
package cmdctx

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"

	appconfig "github.com/sufield/stave/internal/app/config"
)

type resolverKey struct{}
type loggerKey struct{}

// WithResolver returns a context carrying the resolved project config resolver.
// Call this once during bootstrap; commands retrieve it via ResolverFromCmd.
func WithResolver(ctx context.Context, eval *appconfig.GovernanceResolver) context.Context {
	return context.WithValue(ctx, resolverKey{}, eval)
}

// ResolverFromCmd retrieves the project config resolver from the command's context.
// Returns nil if the resolver was not set (e.g., for tolerant commands like init/help).
func ResolverFromCmd(cmd *cobra.Command) *appconfig.GovernanceResolver {
	if cmd == nil {
		return nil
	}
	eval, _ := cmd.Context().Value(resolverKey{}).(*appconfig.GovernanceResolver)
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
