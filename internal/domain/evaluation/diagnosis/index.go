package diagnosis

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// unsafeIndex maps (snapshot index, resource ID) -> unsafe status.
type unsafeIndex map[int]map[string]bool

// isUnsafe reports whether the resource was unsafe in the given snapshot.
func (idx unsafeIndex) isUnsafe(snapIdx int, assetID string) bool {
	return idx[snapIdx][assetID]
}

// isAssetUnsafeAnyControl checks if a resource matches any control's unsafe_predicate.
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
		idx[snapIdx] = make(map[string]bool, len(snap.Resources))
		for _, r := range snap.Resources {
			idx[snapIdx][r.ID.String()] = isAssetUnsafeAnyControl(r, controls)
		}
	}
	return idx
}
