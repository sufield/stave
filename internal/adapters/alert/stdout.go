// Package alert provides AlertSink implementations for the watch monitor.
package alert

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/core/ports"
)

// StdoutSink writes one-line alert summaries to an io.Writer.
type StdoutSink struct {
	W io.Writer
}

var _ ports.AlertSink = (*StdoutSink)(nil)

// Emit writes a single-line alert summary.
func (s *StdoutSink) Emit(_ context.Context, a ports.WatchAlert) error {
	ts := a.Timestamp.UTC().Format("2006-01-02T15:04:05Z")

	switch a.Transition {
	case ports.TransitionError:
		_, err := fmt.Fprintf(s.W, "[%s] WATCH  state=ERROR  %s\n", ts, a.ErrorMessage)
		return err
	case ports.TransitionStable:
		_, err := fmt.Fprintf(s.W, "[%s] WATCH  state=%s violations=%d (no change)\n",
			ts, a.SecurityState, a.Violations)
		return err
	case ports.TransitionRecovery:
		_, err := fmt.Fprintf(s.W, "[%s] WATCH  state=%s violations=%d (recovered)\n",
			ts, a.SecurityState, a.Violations)
		return err
	default:
		parts := []string{
			fmt.Sprintf("[%s] WATCH  state=%s violations=%d new=%d",
				ts, a.SecurityState, a.Violations, a.NewViolations),
		}
		if len(a.Regressions) > 0 {
			parts = append(parts, fmt.Sprintf("regressions=[%s]", strings.Join(a.Regressions, ",")))
		}
		if a.MaxDwellTimeHours > 0 {
			parts = append(parts, fmt.Sprintf("max_dwell=%.0fh", a.MaxDwellTimeHours))
		}
		if a.ActiveSLABreaches > 0 {
			parts = append(parts, fmt.Sprintf("sla_breaches=%d", a.ActiveSLABreaches))
		}
		_, err := fmt.Fprintln(s.W, strings.Join(parts, " "))
		return err
	}
}

// Close is a no-op for stdout.
func (s *StdoutSink) Close() error { return nil }
