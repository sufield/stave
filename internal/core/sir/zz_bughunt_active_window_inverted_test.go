package sir

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestBugHunt_ActiveWindowNotInvertedWhenNowBeforeExposure proves the SIR
// builder never emits an inverted exposure window (End before Start).
//
// exposureWindowsFromLifecycles emits one ExposureWindow per still-active
// lifecycle as {Start: lc.FirstExposedAt(), End: now}. It did so
// unconditionally, with no check that now is at or after the window start.
// When the evaluation instant (`now` / --eval-time) precedes the observation that
// opened the active window — e.g. an audit replayed at an earlier `now`, or
// a snapshot captured after the requested evaluation time — End (now) lands
// BEFORE Start, producing a negative-duration window.
//
// The engine's own ExposureDuration treats now < window-start as an error
// (no valid duration); the SIR builder must not silently hand a malformed,
// inverted window to the downstream Z3 solver, which reasons over these
// windows to grade dwell time. As of `now`, an exposure that opens in the
// future has not occurred, so the window must be omitted (never inverted).
func TestBugHunt_ActiveWindowNotInvertedWhenNowBeforeExposure(t *testing.T) {
	t.Parallel()

	a := asset.Asset{
		ID:     asset.ID("arn:aws:s3:::bucket-future"),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
	}
	lc, err := asset.NewExposureLifecycle(a)
	if err != nil {
		t.Fatalf("NewExposureLifecycle: %v", err)
	}

	// The exposure is observed AFTER the evaluation instant: the active
	// window opens at now+1h, while Build is called with now = fixedTime.
	future := fixedTime.Add(time.Hour)
	if rerr := lc.RecordCheck(future, true); rerr != nil {
		t.Fatalf("RecordCheck(future, exposed): %v", rerr)
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

	for i, w := range doc.Temporal.Windows {
		if w.End.Before(w.Start) {
			t.Errorf("Windows[%d] is inverted: Start=%s End=%s (End before Start). "+
				"An active window opening after `now` must be omitted, not emitted "+
				"with End=now < Start", i, w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
		}
	}
}
