package engine

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// BuildTimelinesPerControl constructs chronological timelines for each asset across all controls.
//
// MVP 1.0 Semantics:
// - Absence of an asset in a snapshot does NOT imply it is safe (no new evidence).
// - Episodes array only contains COMPLETED episodes (unsafe -> safe transition).
// - Open episodes (unsafe at end of input) are tracked via the timeline's state fields.
func BuildTimelinesPerControl(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	predicateParser func(any) (*policy.UnsafePredicate, error),
) map[kernel.ControlID]map[asset.ID]*asset.Timeline {

	// Initialize result map with capacity hints.
	timelinesByControl := make(map[kernel.ControlID]map[asset.ID]*asset.Timeline, len(controls))
	for _, ctl := range controls {
		timelinesByControl[ctl.ID] = make(map[asset.ID]*asset.Timeline)
	}

	// Iterate through Snapshots -> Assets -> Controls.
	// This "pivots" the data into the requested shape in O(S*A*C) time,
	// but only traverses the snapshot list once.
	for _, snap := range snapshots {
		captureTime := snap.CapturedAt

		for _, a := range snap.Assets {
			for _, ctl := range controls {
				timelines := timelinesByControl[ctl.ID]

				// Get or initialize timeline.
				t, exists := timelines[a.ID]
				if !exists {
					t = asset.NewTimeline(a)
					timelines[a.ID] = t
				}

				// Evaluate and record.
				isUnsafe := checkUnsafe(ctl, a, snap, predicateParser)
				t.RecordObservation(captureTime, isUnsafe)

				// Always update the materialized asset to the most recent version.
				t.SetAsset(a)
			}
		}
	}

	return timelinesByControl
}

// checkUnsafe encapsulates the logic to evaluate an asset against a control predicate.
func checkUnsafe(
	ctl policy.ControlDefinition,
	a asset.Asset,
	snap asset.Snapshot,
	parser func(any) (*policy.UnsafePredicate, error),
) bool {
	ctx := policy.NewAssetEvalContextWithIdentities(a, ctl.Params, snap.Identities)
	ctx.PredicateParser = parser
	return ctl.UnsafePredicate.EvaluateWithContext(ctx)
}
