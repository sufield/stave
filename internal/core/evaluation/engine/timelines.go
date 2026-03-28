package engine

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// BuildTimelinesPerControl constructs chronological timelines for each asset across all controls.
func BuildTimelinesPerControl(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	celEval PredicateEvaluator,
) (map[kernel.ControlID]map[asset.ID]*asset.Timeline, error) {

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
					var err error
					t, err = asset.NewTimeline(a)
					if err != nil {
						return nil, fmt.Errorf("build timeline for control %s: %w", ctl.ID, err)
					}
					timelines[a.ID] = t
				}

				isUnsafe := checkUnsafe(ctl, a, snap, celEval)
				if err := t.RecordObservation(captureTime, isUnsafe); err != nil {
					return nil, fmt.Errorf("record observation for control %s, asset %s: %w", ctl.ID, a.ID, err)
				}
				t.SetAsset(a)
			}
		}
	}

	return timelinesByControl, nil
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
