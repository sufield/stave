package risk

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestComputeItems_DisappearingAsset(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:   "CTL.TEST.001",
		Type: policy.TypeUnsafeDuration,
		Params: policy.NewParams(map[string]any{
			"max_unsafe_duration": "1h",
		}),
	}
	ctl.Prepare()

	now := time.Now().UTC()
	t1 := now.Add(-2 * time.Hour)
	t2 := now.Add(-1 * time.Hour)

	// Snapshot 1: Asset A is UNSAFE
	snap1 := asset.Snapshot{
		CapturedAt: t1,
		Assets: []asset.Asset{
			{ID: "asset-a", Type: "test-type"},
		},
	}

	// Snapshot 2: Asset A is MISSING (e.g. deleted but not remediated, or lost visibility)
	snap2 := asset.Snapshot{
		CapturedAt: t2,
		Assets:     []asset.Asset{},
	}

	req := ThresholdRequest{
		Controls:                []policy.ControlDefinition{ctl},
		Snapshots:               []asset.Snapshot{snap1, snap2},
		GlobalMaxUnsafeDuration: 24 * time.Hour,
		Now:                     now,
		PredicateEval: func(ctl policy.ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (bool, error) {
			// Always unsafe for this test
			return true, nil
		},
	}

	items := ComputeItems(req)

	// BUG: If asset-a was unsafe in snap1, and missing in snap2,
	// computeAssetStates should NOT treat it as safe.
	// Current implementation: computeAssetStates only updates assets present in the snapshot.
	// Actually, wait.

	// Let's re-read computeAssetStates:
	/*
		for _, snap := range snapshots {
			for _, a := range snap.Assets {
				// ... updates states[a.ID]
			}
		}
	*/
	// If an asset is NOT in snap.Assets, it's NOT in the inner loop.
	// So states[a.ID].CurrentlyUnsafe remains TRUE if it was true before!

	// WAIT. I misread the code in the previous turn.
	/*
		if result {
			// ...
			st.CurrentlyUnsafe = true
		} else {
			// ...
			st.CurrentlyUnsafe = false
		}
	*/
	// If the asset is missing, CurrentlyUnsafe stays true.
	// And ComputeItems checks:
	/*
		for id, st := range states {
			if !st.CurrentlyUnsafe || st.FirstUnsafeAt.IsZero() {
				continue
			}
	*/
	// So disappearing assets STAY unsafe in risk calculation!
	// This means if you delete a resource, it still shows up as a risk item.
	// That's also a bug! It should probably be resolved if it's gone from the latest snapshot.

	// Correct behavior: a disappearing asset preserves its streak.
	// Absence is not remediation — the asset may have been deleted
	// without being fixed. The streak should be frozen, not reset.
	found := false
	for _, item := range items {
		if item.AssetID == "asset-a" {
			found = true
		}
	}

	if !found {
		t.Errorf("disappearing asset should preserve its risk streak — absence is not remediation")
	}
}
