package diagnosis

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// unsafeIndex maps (snapshot index, asset ID) -> unsafe status.
type unsafeIndex map[int]map[string]bool

// isUnsafe reports whether the asset was unsafe in the given snapshot.
func (idx unsafeIndex) isUnsafe(snapIdx int, assetID string) bool {
	return idx[snapIdx][assetID]
}

// isAssetUnsafeAnyControl checks if an asset matches any control's unsafe_predicate.
func isAssetUnsafeAnyControl(r asset.Asset, controls []policy.ControlDefinition) bool {
	for _, ctl := range controls {
		if ctl.UnsafePredicate.Evaluate(r, ctl.Params) {
			return true
		}
	}
	return false
}

func buildUnsafeAnyControlBySnapshotAsset(snapshots []asset.Snapshot, controls []policy.ControlDefinition) unsafeIndex {
	idx := make(unsafeIndex, len(snapshots))
	for snapIdx, snap := range snapshots {
		idx[snapIdx] = make(map[string]bool, len(snap.Assets))
		for _, r := range snap.Assets {
			idx[snapIdx][r.ID.String()] = isAssetUnsafeAnyControl(r, controls)
		}
	}
	return idx
}
