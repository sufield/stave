package compose

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
)

// CommandContext returns cmd.Context(). Panics if cmd is nil —
// a missing command indicates a programming error, not a runtime condition.
func CommandContext(cmd *cobra.Command) context.Context {
	return cmd.Context()
}

// ResolveNow parses a --now flag value. Returns wall clock UTC when raw is empty.
func ResolveNow(raw string) (time.Time, error) {
	if raw == "" {
		return time.Now().UTC(), nil
	}
	return cliflags.ParseRFC3339(raw, "--now")
}

// ResolveFormatValue determines the effective output format from a flag value and
// global JSON mode. When the flag was not explicitly changed and global JSON mode
// is active, "json" is used instead.
func ResolveFormatValue(cmd *cobra.Command, raw string) (appcontracts.OutputFormat, error) {
	formatRaw := cliflags.ResolveFormat(cmd, raw)
	return ui.ParseOutputFormat(strings.ToLower(formatRaw))
}

// ResolveFormatValuePure determines the effective output format without cobra.
// formatChanged indicates whether --format was explicitly set by the user.
func ResolveFormatValuePure(raw string, formatChanged bool, isJSONMode bool) (appcontracts.OutputFormat, error) {
	formatRaw := cliflags.ResolveFormatPure(raw, formatChanged, isJSONMode)
	return ui.ParseOutputFormat(strings.ToLower(formatRaw))
}

// EmptyDash returns "-" if the string is whitespace-only.
func EmptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
