package sir

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestBugHunt_ClampedWindowFlaggedDurationUnreliable proves that an exposure
// window the source lifecycle clamped to zero duration is surfaced in the SIR
// with DurationUnreliable=true, not as a trustworthy zero-dwell exposure.
//
// When a secure observation lands at or before the unsafe observation that
// opened a window (clock skew / snapshot reorder), ExposureWindow.Resolve
// clamps the window to Start == End and the lifecycle records
// HasClampedWindow. The engine renders that lifecycle Inconclusive — it
// refuses to credit the zero dwell for SLA math. The SIR builder, however,
// emitted the window with Start == End and no reliability signal, so the Z3
// solver would read it as "exposed for 0s" and prove "within any SLA
// threshold" — an unsound conclusion drawn from data the engine deemed
// unusable.
//
// Correct behavior: the emitted window carries DurationUnreliable=true so the
// solver declines to grade dwell from it (the same stance it takes on a
// CoverageGap), while a normal positive-duration window stays reliable.
func TestBugHunt_ClampedWindowFlaggedDurationUnreliable(t *testing.T) {
	t.Parallel()

	a := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-skew"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
	}
	lc, err := asset.NewExposureLifecycle(a)
	if err != nil {
		t.Fatalf("NewExposureLifecycle: %v", err)
	}

	// Unsafe observed at t1, then "secure" observed at t0 < t1 (a reordered /
	// skewed snapshot). Resolve clamps the window to zero duration.
	t1 := fixedTime.Add(-2 * time.Hour)
	t0 := fixedTime.Add(-3 * time.Hour)
	if rerr := lc.RecordCheck(t1, true); rerr != nil {
		t.Fatalf("RecordCheck(t1, exposed): %v", rerr)
	}
	if rerr := lc.RecordCheck(t0, false); rerr != nil {
		t.Fatalf("RecordCheck(t0, secure): %v", rerr)
	}
	if !lc.HasClampedWindow() {
		t.Fatalf("precondition: expected a clamped window in the lifecycle")
	}

	src := &fakeLifecycleSource{
		source: map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle{
			kernel.ControlID("CTL.S3.PUBLIC.001"): {a.ID: lc},
		},
	}
	b := NewBuilder(WithLifecycleSource(src))
	doc, err := b.Build(
		[]controldef.ControlDefinition{sampleControl()},
		[]asset.Snapshot{sampleSnapshot(fixedTime)},
		fixedTime,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(doc.Temporal.Windows) != 1 {
		t.Fatalf("want 1 emitted window, got %d", len(doc.Temporal.Windows))
	}
	w := doc.Temporal.Windows[0]
	if !w.Start.Equal(w.End) {
		t.Fatalf("precondition: expected a zero-duration (clamped) window, got Start=%s End=%s",
			w.Start, w.End)
	}
	if !w.DurationUnreliable {
		t.Errorf("clamped zero-duration window must be flagged DurationUnreliable=true so the "+
			"solver declines to grade dwell; got false (Start==End=%s would read as a "+
			"trustworthy 0s exposure)", w.Start.Format(time.RFC3339))
	}
}
