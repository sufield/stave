package engine

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// BuildTimelinesPerControl constructs timelines for each asset, per control.
//
// MVP 1.0 Semantics:
// - Absence of an asset in a snapshot does NOT imply safe (no new evidence)
// - Episodes only contain completed episodes (true -> false transitions)
// - Open episodes remain represented by timeline open-state timestamps
func BuildTimelinesPerControl(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	predicateParser func(any) (*policy.UnsafePredicate, error),
) map[kernel.ControlID]map[string]*asset.Timeline {
	// map[controlID][assetID]*asset.Timeline
	result := make(map[kernel.ControlID]map[string]*asset.Timeline)

	for _, ctl := range controls {
		timelines := make(map[string]*asset.Timeline)
		result[ctl.ID] = timelines

		for _, snapshot := range snapshots {
			recordSnapshotForControl(timelines, ctl, snapshot, predicateParser)
		}

		// NOTE: We intentionally do NOT close episodes when:
		// 1. Asset disappears from latest snapshot (absence != safe)
		// 2. Asset is still unsafe at end of input (open episodes stay open)
		//
		// Episodes array only contains COMPLETED episodes (true -> false).
		// Open episode state is tracked on timeline state fields.
	}

	for _, ctl := range controls {
		if _, ok := result[ctl.ID]; !ok {
			panic("postcondition failed: BuildTimelinesPerControl missing entry for control " + string(ctl.ID))
		}
	}

	return result
}

func recordSnapshotForControl(
	timelines map[string]*asset.Timeline,
	ctl policy.ControlDefinition,
	snapshot asset.Snapshot,
	predicateParser func(any) (*policy.UnsafePredicate, error),
) {
	for _, a := range snapshot.Assets {
		timeline := getOrCreateTimeline(timelines, a)
		isUnsafe := isAssetUnsafeForControl(ctl, a, snapshot, predicateParser)

		timeline.RecordObservation(snapshot.CapturedAt, isUnsafe)
		// Always keep the latest observed asset materialized on the timeline.
		timeline.SetAsset(a)
	}
}

func getOrCreateTimeline(
	timelines map[string]*asset.Timeline,
	a asset.Asset,
) *asset.Timeline {
	assetID := a.ID.String()
	timeline, exists := timelines[assetID]
	if exists {
		return timeline
	}

	timeline = asset.NewTimeline(a)
	timelines[assetID] = timeline
	return timeline
}

func isAssetUnsafeForControl(
	ctl policy.ControlDefinition,
	a asset.Asset,
	snapshot asset.Snapshot,
	predicateParser func(any) (*policy.UnsafePredicate, error),
) bool {
	ctx := policy.NewAssetEvalContextWithIdentities(a, ctl.Params, snapshot.Identities)
	ctx.PredicateParser = predicateParser
	return ctl.UnsafePredicate.EvaluateWithContext(ctx)
}
