package logging

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestWarnAccumulator(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	acc := NewWarnAccumulator(inner)
	logger := slog.New(acc)

	logger.Warn("w1")
	logger.Warn("w2")
	logger.Error("e1")

	if got := acc.Suppressed(); got != 2 {
		t.Fatalf("Suppressed() = %d, want 2", got)
	}
	if !bytes.Contains(buf.Bytes(), []byte("e1")) {
		t.Fatal("error record should pass through")
	}
	if bytes.Contains(buf.Bytes(), []byte("w1")) {
		t.Fatal("warn record should be suppressed")
	}
}

func TestWarnAccumulator_WithAttrsSharesCount(t *testing.T) {
	inner := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	acc := NewWarnAccumulator(inner)
	derived := slog.New(acc.WithAttrs([]slog.Attr{slog.String("k", "v")}))

	derived.Warn("from derived")
	if got := acc.Suppressed(); got != 1 {
		t.Fatalf("Suppressed() = %d, want 1 (shared counter)", got)
	}
}
