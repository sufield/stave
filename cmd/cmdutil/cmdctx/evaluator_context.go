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
//
// A wrong-type value in the context slot indicates a bootstrap bug
// (someone stored the wrong concrete type under resolverKey) and is
// logged at WARN — silently dropping it would mask the
// misconfiguration. Tolerant commands proceed with nil; strict
// commands surface the missing-resolver error themselves.
func ResolverFromCmd(cmd *cobra.Command) *appconfig.GovernanceResolver {
	if cmd == nil {
		return nil
	}
	raw := cmd.Context().Value(resolverKey{})
	if raw == nil {
		return nil
	}
	eval, ok := raw.(*appconfig.GovernanceResolver)
	if !ok {
		slog.Warn("cmdctx: resolverKey context value is not *appconfig.GovernanceResolver — bootstrap bug",
			"actual_type", "non-resolver value")
		return nil
	}
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
