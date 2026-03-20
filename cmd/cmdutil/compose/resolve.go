package compose

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// CommandContext returns cmd.Context() with a fallback to context.Background().
func CommandContext(cmd *cobra.Command) context.Context {
	if cmd == nil {
		return context.Background()
	}
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// ResolveNow parses a --now flag value. Returns wall clock UTC when raw is empty.
func ResolveNow(raw string) (time.Time, error) {
	if raw == "" {
		return time.Now().UTC(), nil
	}
	return timeutil.ParseRFC3339(raw, "--now")
}

// ResolveFormatValue determines the effective output format from a flag value and
// global JSON mode. When the flag was not explicitly changed and global JSON mode
// is active, "json" is used instead.
func ResolveFormatValue(cmd *cobra.Command, raw string) (ui.OutputFormat, error) {
	formatRaw := cmdutil.ResolveFormat(cmd, raw)
	return ui.ParseOutputFormat(strings.ToLower(formatRaw))
}

// ResolveFormatValuePure determines the effective output format without cobra.
// formatChanged indicates whether --format was explicitly set by the user.
func ResolveFormatValuePure(raw string, formatChanged bool, isJSONMode bool) (ui.OutputFormat, error) {
	formatRaw := cmdutil.ResolveFormatPure(raw, formatChanged, isJSONMode)
	return ui.ParseOutputFormat(strings.ToLower(formatRaw))
}

// EmptyDash returns "-" if the string is whitespace-only.
func EmptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
