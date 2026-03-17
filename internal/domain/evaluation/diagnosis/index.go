package diagnosis

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// unsafeKey uniquely identifies an asset's state at a specific point in time.
type unsafeKey struct {
	snapIdx int
	assetID asset.ID
}

// unsafeIndex tracks which assets were considered unsafe across multiple snapshots.
type unsafeIndex struct {
	violations map[unsafeKey]struct{}
}

// isUnsafe reports whether the asset matched any unsafe predicate in the given snapshot.
func (idx *unsafeIndex) isUnsafe(snapIdx int, assetID asset.ID) bool {
	if idx == nil || idx.violations == nil {
		return false
	}
	_, ok := idx.violations[unsafeKey{snapIdx, assetID}]
	return ok
}

// buildUnsafeIndex constructs a lookup of all unsafe states across snapshots.
func buildUnsafeIndex(snapshots []asset.Snapshot, controls []policy.ControlDefinition, parser policy.PredicateParser) *unsafeIndex {
	idx := &unsafeIndex{
		violations: make(map[unsafeKey]struct{}),
	}

	for sIdx, snap := range snapshots {
		for _, a := range snap.Assets {
			if matchesAnyControl(a, snap, controls, parser) {
				idx.violations[unsafeKey{sIdx, a.ID}] = struct{}{}
			}
		}
	}

	return idx
}

// matchesAnyControl checks if an asset matches any control's unsafe_predicate.
func matchesAnyControl(a asset.Asset, snap asset.Snapshot, controls []policy.ControlDefinition, parser policy.PredicateParser) bool {
	for i := range controls {
		ctx := policy.NewAssetEvalContext(a, controls[i].Params, snap.Identities...)
		ctx.PredicateParser = parser
		if controls[i].UnsafePredicate.EvaluateWithContext(ctx) {
			return true
		}
	}
	return false
}
