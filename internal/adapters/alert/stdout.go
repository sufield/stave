// Package alert provides AlertSink implementations for the watch monitor.
package alert

import (
	"context"
	"fmt"
	"io"

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
	_, err := fmt.Fprintln(s.W, a.FormatLine(ts))
	return err
}

// Close is a no-op for stdout.
func (s *StdoutSink) Close() error { return nil }
