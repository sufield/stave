package asset

import (
	"testing"
	"time"
)

// TestBugHunt_ZeroNowExposureDuration proves the bug at
// internal/core/asset/lifecycle.go:256 (ExposureLifecycle.ExposureDuration).
//
// The guard at line 260 reads:
//
//	if !now.IsZero() && now.Before(l.activeWindow.OpenedAt()) { ... return error }
//
// When `now` is the zero time, `now.IsZero()` short-circuits the guard, so
// execution falls through to `return now.Sub(l.activeWindow.OpenedAt()), nil`.
// That computes time.Time{}.Sub(openedAt) — a large NEGATIVE duration — and
// returns it with a nil error.
//
// A zero `now` logically precedes any real OpenedAt, exactly like the
// now.Before(openedAt) case, so it should be rejected with an error (or at
// minimum never yield a negative dwell time). This test asserts that correct
// behavior and therefore FAILS against the current buggy code.
func TestBugHunt_ZeroNowExposureDuration(t *testing.T) {
	l, err := NewExposureLifecycle(Asset{ID: "bug-zero-now"})
	if err != nil {
		t.Fatalf("NewExposureLifecycle: unexpected error: %v", err)
	}

	// Open an active exposure window with a real, non-zero OpenedAt.
	openedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.handleExposed(openedAt)

	if !l.HasActiveWindow() {
		t.Fatalf("precondition failed: expected an active exposure window")
	}
	if l.FirstExposedAt().IsZero() {
		t.Fatalf("precondition failed: expected a non-zero OpenedAt")
	}

	// Query duration with a zero `now`. A zero `now` precedes any real
	// window start, so this must be rejected like the now.Before(openedAt)
	// case — and must NEVER return a negative duration with a nil error.
	d, err := l.ExposureDuration(time.Time{})

	if err != nil {
		// Correct behavior: zero `now` rejected. Bug not present.
		return
	}

	if d < 0 {
		t.Fatalf("ExposureDuration(zero now) returned negative duration %v with nil error; "+
			"a zero `now` precedes any real window start (%s) and must be rejected, "+
			"not yield a nonsense negative dwell time", d, openedAt.Format(time.RFC3339))
	}
}
