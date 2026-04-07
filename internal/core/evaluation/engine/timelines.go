package engine

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// BuildTimelinesPerControl constructs chronological timelines for each asset
// across all controls. The outer loop iterates snapshots (time), the middle
// loop iterates assets, and the inner loop evaluates each control's predicate
// to record whether the asset was unsafe at that point in time.
func BuildTimelinesPerControl(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	celEval policy.PredicateEval,
) (map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, error) {

	timelinesByControl := make(map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle, len(controls))
	for _, ctl := range controls {
		timelinesByControl[ctl.ID] = make(map[asset.ID]*asset.ExposureLifecycle)
	}

	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			if err := recordAssetObservation(a, snap, controls, celEval, timelinesByControl); err != nil {
				return nil, err
			}
		}
	}

	return timelinesByControl, nil
}

// recordAssetObservation evaluates a single asset against all controls at one
// point in time, updating the corresponding timelines. Extracted from the
// triple-nested loop to reduce indentation and clarify the per-asset logic.
func recordAssetObservation(
	a asset.Asset,
	snap asset.Snapshot,
	controls []policy.ControlDefinition,
	celEval policy.PredicateEval,
	timelinesByControl map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle,
) error {
	for _, ctl := range controls {
		timelines := timelinesByControl[ctl.ID]

		t, exists := timelines[a.ID]
		if !exists {
			t = asset.NewExposureLifecycle(a)
			timelines[a.ID] = t
		}

		isUnsafe := checkUnsafe(ctl, a, snap, celEval)
		if err := t.RecordCheck(snap.CapturedAt, isUnsafe); err != nil {
			return fmt.Errorf("record observation for control %s, asset %s: %w", ctl.ID, a.ID, err)
		}
		t.SetAsset(a)
	}
	return nil
}

// checkUnsafe evaluates an asset against a control predicate using the CEL evaluator.
func checkUnsafe(
	ctl policy.ControlDefinition,
	a asset.Asset,
	snap asset.Snapshot,
	celEval policy.PredicateEval,
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
