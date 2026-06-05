package asset

import (
	"strings"
	"testing"
	"time"
)

// TestBugHunt_SummaryNegativeHours proves the bug at
// internal/core/asset/lifecycle.go:421 (ExposureLifecycle.FormatExposureSummary).
//
// FormatExposureSummary calls ExposureDuration(now) and only takes the
// "duration unavailable" branch when ExposureDuration returns an error.
// Because ExposureDuration(time.Time{}) returns a large NEGATIVE duration
// with a nil error (the zero-now guard at line 260 short-circuits on
// now.IsZero()), FormatExposureSummary with a zero `now` falls through to
// lines 432-437 and renders int(math.Round(d.Hours())) for a large
// negative d.
//
// The result is a string like
//
//	"Asset non-compliant for -8765... hours (SLA: 168 hours). Exposed since ..."
//
// With an active window and a zero/invalid `now`, FormatExposureSummary
// should render the "duration unavailable" fallback (or a non-negative
// hour count) — never a large negative hours figure. This test asserts
// that correct behavior and therefore FAILS against the current buggy code.
func TestBugHunt_SummaryNegativeHours(t *testing.T) {
	l, err := NewExposureLifecycle(Asset{ID: "bug-summary-neg-hours"})
	if err != nil {
		t.Fatalf("NewExposureLifecycle: unexpected error: %v", err)
	}

	// Open an active exposure window with a real, non-zero OpenedAt.
	openedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.handleExposed(openedAt)

	if !l.HasActiveWindow() {
		t.Fatalf("precondition failed: expected an active exposure window")
	}

	threshold := 168 * time.Hour // 7d SLA

	// Render the summary with a zero `now`. A zero `now` precedes any real
	// window start; the summary must not render a negative hour count.
	summary := l.FormatExposureSummary(threshold, time.Time{})

	// Correct behavior: either the "duration unavailable" fallback, or a
	// non-negative hour count. A negative "non-compliant for -N hours"
	// figure is the bug.
	if strings.Contains(summary, "non-compliant for -") {
		t.Fatalf("FormatExposureSummary(zero now) rendered a negative hours figure: %q; "+
			"with a zero/invalid `now` it must render the 'duration unavailable' "+
			"fallback or a non-negative hour count, never a negative dwell time",
			summary)
	}
}
