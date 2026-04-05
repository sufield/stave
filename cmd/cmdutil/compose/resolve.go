package compose

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
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

// ResolveClock returns a FixedClock if a timestamp is provided, otherwise RealClock.
func ResolveClock(raw string) (ports.Clock, error) {
	if raw == "" {
		return ports.RealClock{}, nil
	}
	t, err := cliflags.ParseRFC3339(raw, "--now")
	if err != nil {
		return nil, err
	}
	return ports.FixedClock(t), nil
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

// ResolveNowDiag parses a --now flag value and returns a diagnostic issue on failure.
// Use this instead of inline ParseRFC3339 + diag.Diagnostic construction.
func ResolveNowDiag(raw string) (time.Time, *diag.Diagnostic) {
	t, err := cliflags.ParseRFC3339(raw, "--now")
	if err != nil {
		issue := diag.New(diag.CodeInvalidNowTime).
			Error().
			Action("Use RFC3339 format").
			Command("stave validate --now 2026-01-15T00:00:00Z").
			With("value", raw).
			WithSensitive("error", err.Error()).
			Build()
		return time.Time{}, &issue
	}
	return t, nil
}

// ResolveDurationDiag parses a duration flag value and returns a diagnostic issue on failure.
// Use this instead of inline kernel.ParseDuration + diag.Diagnostic construction.
func ResolveDurationDiag(raw string) (*time.Duration, *diag.Diagnostic) {
	dur, err := kernel.ParseDuration(raw)
	if err != nil {
		issue := diag.New(diag.CodeInvalidMaxUnsafe).
			Error().
			Action("Use format like 168h, 7d, or 1d12h").
			Command("stave validate --max-unsafe 168h").
			With("value", raw).
			WithSensitive("error", err.Error()).
			Build()
		return nil, &issue
	}
	return &dur, nil
}

// EmptyDash returns "-" if the string is whitespace-only.
func EmptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
