// Package alert provides AlertSink implementations for the watch monitor.
package alert

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/ports"
)

// ErrSinkNotInitialized is returned when an alert sink's underlying
// writer / handle is nil. Sinks construct cleanly via their
// New* constructors; the sentinel surfaces the misuse case where
// callers built a sink via zero-value struct literal and skipped
// the constructor's nil-check.
var ErrSinkNotInitialized = errors.New("alert sink not initialized: use the package New* constructor")

// StdoutSink writes one-line alert summaries to an io.Writer.
// Construct via NewStdoutSink to enforce the non-nil-writer invariant;
// a zero-value StdoutSink fails Emit with ErrSinkNotInitialized.
type StdoutSink struct {
	W io.Writer
}

var _ ports.AlertSink = (*StdoutSink)(nil)

// NewStdoutSink validates that w is non-nil and returns a ready-to-use
// StdoutSink. Returns ErrSinkNotInitialized when w is nil so callers
// fail at construction rather than discovering the problem on the
// first emit.
func NewStdoutSink(w io.Writer) (*StdoutSink, error) {
	if w == nil {
		return nil, ErrSinkNotInitialized
	}
	return &StdoutSink{W: w}, nil
}

// Emit writes a single-line alert summary.
//
// A nil receiver writer returns ErrSinkNotInitialized rather than
// panicking inside fmt.Fprintln — the watch monitor surfaces the
// error to the operator and stops driving the sink.
func (s *StdoutSink) Emit(_ context.Context, a ports.WatchAlert) error {
	if s.W == nil {
		return ErrSinkNotInitialized
	}
	ts := a.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
	_, err := fmt.Fprintln(s.W, a.FormatLine(ts))
	return err
}

// Close is a no-op for stdout.
func (s *StdoutSink) Close() error { return nil }
