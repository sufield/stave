package asset

import (
	"testing"
	"time"
)

// TestExposureLifecycle_SecureClosesWindowAtSecureObservation verifies that
// when the asset is observed secure at time t, the resolved exposure
// window closes at t (not at the last unsafe observation). Closing at the
// last unsafe observation would undercount dwell time by one observation interval.
func TestExposureLifecycle_SecureClosesWindowAtSecureObservation(t *testing.T) {
	l, _ := NewExposureLifecycle(Asset{ID: "x"})

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	l.handleExposed(t0) // window opens at t0
	l.handleExposed(t1) // still unsafe at t1 (lastObservedAt = t1)
	l.handleSecure(t2)  // observed secure at t2

	if l.history.Count() != 1 {
		t.Fatalf("expected 1 resolved window, got %d", l.history.Count())
	}
	resolved := l.history.windows[0]

	if !resolved.OpenedAt().Equal(t0) {
		t.Errorf("OpenedAt = %s, want %s", resolved.OpenedAt(), t0)
	}
	if !resolved.ResolvedAt().Equal(t2) {
		t.Errorf("ResolvedAt = %s, want %s (the secure observation, NOT the last unsafe observation at %s)",
			resolved.ResolvedAt(), t2, t1)
	}
}
