package compose

import (
	"context"
	"fmt"
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
	t, err := cliflags.ParseRFC3339(raw, "--now")
	if err != nil {
		return time.Time{}, fmt.Errorf("parse --now: %w", err)
	}
	return t, nil
}

// ResolveClock returns a FixedClock if a timestamp is provided, otherwise RealClock.
func ResolveClock(raw string) (ports.Clock, error) {
	if raw == "" {
		return ports.RealClock{}, nil
	}
	t, err := cliflags.ParseRFC3339(raw, "--now")
	if err != nil {
		return nil, fmt.Errorf("parse --now: %w", err)
	}
	return ports.FixedClock(t), nil
}

// ResolveFormatValue parses the --format flag value into an
// [appcontracts.OutputFormat]. Takes only the raw string — the
// earlier signature accepted *cobra.Command but never consulted
// it (the underlying resolver was a plain TrimSpace wrapper).
// Callers previously reading "was the flag explicitly set" via
// cobra should capture that in PreRunE onto their Options struct
// and reference it from there; format resolution itself does not
// need the information.
func ResolveFormatValue(raw string) (appcontracts.OutputFormat, error) {
	f, err := ui.ParseOutputFormat(raw)
	if err != nil {
		return "", fmt.Errorf("parse output format: %w", err)
	}
	return f, nil
}

// ResolveNowDiag parses a --now flag value and returns a diagnostic issue on failure.
// Use this instead of inline ParseRFC3339 + diag.Finding construction.
func ResolveNowDiag(raw string) (time.Time, *diag.Finding) {
	t, err := cliflags.ParseRFC3339(raw, "--now")
	if err != nil {
		issue := diag.NewFinding(diag.RuleInvalidNowTime).
			Error().
			Remediation("Use RFC3339 format").
			FixCommand("stave validate --now 2026-01-15T00:00:00Z").
			Attribute("value", raw).
			SensitiveAttribute("error", err.Error()).
			Build()
		return time.Time{}, &issue
	}
	return t, nil
}

// ResolveDurationDiag parses a duration flag value and returns a diagnostic issue on failure.
// Use this instead of inline kernel.ParseDuration + diag.Finding construction.
func ResolveDurationDiag(raw string) (*time.Duration, *diag.Finding) {
	dur, err := kernel.ParseDuration(raw)
	if err != nil {
		issue := diag.NewFinding(diag.RuleInvalidMaxUnsafe).
			Error().
			Remediation("Use format like 168h, 7d, or 1d12h").
			FixCommand("stave validate --max-unsafe 168h").
			Attribute("value", raw).
			SensitiveAttribute("error", err.Error()).
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
