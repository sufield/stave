package asset

import (
	"testing"
	"time"
)

// TestBugHunt_ZeroSeedSpanInflation proves the bug at
// internal/core/asset/validation.go:98 (newSnapshotTimeline /
// snapshotLifecycle.observe, reached via Snapshots.analyze).
//
// analyze() seeds the timeline with s[0].CapturedAt as BOTH earliest and
// latest:
//
//	lifecycle: newSnapshotTimeline(s[0].CapturedAt)
//
// observe() only lowers `earliest` when capturedAt.Before(t.earliest). When the
// first snapshot's CapturedAt is the zero time (a missing timestamp), `earliest`
// is seeded to the zero time (~year 1) and never advances, because no real
// timestamp is Before the zero time. Meanwhile `latest` advances to the real
// maximum. finalize() then computes span = latest - earliest against the zero
// time, producing an enormous span (centuries) instead of the true observation
// span.
//
// Correct behavior: the span must reflect the range between the earliest and
// latest *real* (non-zero) snapshot timestamps. With a zero-timestamped first
// snapshot and real later snapshots, span should be the difference between the
// real timestamps (here exactly 48h), not a centuries-long value anchored at
// the zero time. This test asserts that and therefore FAILS on the current
// buggy code.
func TestBugHunt_ZeroSeedSpanInflation(t *testing.T) {
	// First snapshot has a MISSING (zero) timestamp; the later two carry
	// real timestamps 48h apart.
	tEarlyReal := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	tLateReal := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)

	snaps := Snapshots{
		{CapturedAt: time.Time{}}, // missing timestamp -> seeds earliest=latest=zero
		{CapturedAt: tEarlyReal},
		{CapturedAt: tLateReal},
	}

	ctx := snaps.analyze()
	if ctx == nil || ctx.lifecycle == nil {
		t.Fatalf("precondition failed: analyze() returned nil lifecycle")
	}

	wantSpan := tLateReal.Sub(tEarlyReal) // 48h between the real timestamps
	gotSpan := ctx.lifecycle.span

	// Tolerate nothing extra: the span between the real timestamps is exact.
	if gotSpan != wantSpan {
		t.Fatalf("snapshot span = %v, want %v; the zero (missing) first "+
			"timestamp inflated the span by anchoring `earliest` at the zero "+
			"time (~year 1). earliest=%s latest=%s",
			gotSpan, wantSpan,
			ctx.lifecycle.earliest.Format(time.RFC3339),
			ctx.lifecycle.latest.Format(time.RFC3339))
	}
}
