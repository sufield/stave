package engine

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// BuildTimelinesPerControl constructs chronological timelines for each asset across all controls.
func BuildTimelinesPerControl(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	celEval PredicateEvaluator,
) map[kernel.ControlID]map[asset.ID]*asset.Timeline {

	timelinesByControl := make(map[kernel.ControlID]map[asset.ID]*asset.Timeline, len(controls))
	for _, ctl := range controls {
		timelinesByControl[ctl.ID] = make(map[asset.ID]*asset.Timeline)
	}

	for _, snap := range snapshots {
		captureTime := snap.CapturedAt

		for _, a := range snap.Assets {
			for _, ctl := range controls {
				timelines := timelinesByControl[ctl.ID]

				t, exists := timelines[a.ID]
				if !exists {
					t = asset.NewTimeline(a)
					timelines[a.ID] = t
				}

				isUnsafe := checkUnsafe(ctl, a, snap, celEval)
				t.RecordObservation(captureTime, isUnsafe)
				t.SetAsset(a)
			}
		}
	}

	return timelinesByControl
}

// checkUnsafe evaluates an asset against a control predicate using the CEL evaluator.
func checkUnsafe(
	ctl policy.ControlDefinition,
	a asset.Asset,
	snap asset.Snapshot,
	celEval PredicateEvaluator,
) bool {
	if celEval == nil {
		return false
	}
	result, err := celEval(ctl, a, snap.Identities)
	if err != nil {
		return false
	}
	return result
}
