package logging

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// WarnAccumulator wraps a slog.Handler and silently counts Warn-level
// records instead of emitting them. Error+ always passes through.
// The shared counter lets derived handlers (WithAttrs/WithGroup) report
// a single total.
type WarnAccumulator struct {
	inner slog.Handler
	count *atomic.Int64
}

// NewWarnAccumulator wraps inner so Warn records are counted, not printed.
func NewWarnAccumulator(inner slog.Handler) *WarnAccumulator {
	return &WarnAccumulator{inner: inner, count: &atomic.Int64{}}
}

func (h *WarnAccumulator) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *WarnAccumulator) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn {
		h.count.Add(1)
		return nil
	}
	if err := h.inner.Handle(ctx, r); err != nil {
		return fmt.Errorf("accumulator handle: %w", err)
	}
	return nil
}

func (h *WarnAccumulator) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &WarnAccumulator{inner: h.inner.WithAttrs(attrs), count: h.count}
}

func (h *WarnAccumulator) WithGroup(name string) slog.Handler {
	return &WarnAccumulator{inner: h.inner.WithGroup(name), count: h.count}
}

// Suppressed returns the number of Warn records intercepted.
func (h *WarnAccumulator) Suppressed() int64 {
	return h.count.Load()
}
