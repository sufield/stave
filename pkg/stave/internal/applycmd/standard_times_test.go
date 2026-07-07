package applycmd

import (
	"errors"
	"testing"
	"time"
)

// TestParseStandardTimes pins the reference-clock and duration semantics that
// must match the pre-facade command byte-for-byte. These paths are not covered
// by the e2e goldens (which always pass an explicit UTC --eval-time).
func TestParseStandardTimes(t *testing.T) {
	t.Run("empty --max-unsafe is rejected (exit 2)", func(t *testing.T) {
		// The pre-facade appeval.parseMaxUnsafeDuration parsed unconditionally,
		// so an empty value errored (ErrEmptyDuration). Defaulting it to 0 and
		// evaluating would flip the exit code from 2 to 3.
		_, _, err := parseStandardTimes("", "2026-01-15T00:00:00Z")
		if err == nil {
			t.Fatal("expected empty --max-unsafe to error")
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("empty --max-unsafe error should wrap ErrInvalidInput, got: %v", err)
		}
	})

	t.Run("empty --eval-time materializes the wall clock (not zero)", func(t *testing.T) {
		// The pre-facade command passed ports.RealClock{}.Now() == time.Now().UTC()
		// as a concrete time, so the engine used the wall clock (IsUserProvided=
		// true). A zero time.Time would make the engine fall back to the latest
		// snapshot's CapturedAt, changing durations, security_state, and exit code.
		before := time.Now().UTC()
		_, now, err := parseStandardTimes("168h", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if now.IsZero() {
			t.Fatal("empty --eval-time must materialize the wall clock, got the zero time")
		}
		if now.Before(before) {
			t.Errorf("materialized now %v is before the call started %v", now, before)
		}
		if now.Location() != time.UTC {
			t.Errorf("materialized now must be UTC, got %v", now.Location())
		}
	})

	t.Run("--eval-time is normalized to UTC", func(t *testing.T) {
		// A non-UTC offset must render identically to the pre-facade parseEvalTime
		// which applied .UTC(); otherwise the run.now bytes diverge.
		_, now, err := parseStandardTimes("168h", "2026-01-15T05:00:00+05:00")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
		if !now.Equal(want) || now.Location() != time.UTC {
			t.Errorf("now = %v (loc %v), want %v UTC", now, now.Location(), want)
		}
	})

	t.Run("valid --max-unsafe with day unit", func(t *testing.T) {
		maxUnsafe, _, err := parseStandardTimes("7d", "2026-01-15T00:00:00Z")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if maxUnsafe != 7*24*time.Hour {
			t.Errorf("maxUnsafe = %v, want 168h", maxUnsafe)
		}
	})

	t.Run("bad --eval-time is rejected (exit 2)", func(t *testing.T) {
		_, _, err := parseStandardTimes("168h", "not-a-time")
		if err == nil {
			t.Fatal("expected bad --eval-time to error")
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("bad --eval-time error should wrap ErrInvalidInput, got: %v", err)
		}
	})
}
