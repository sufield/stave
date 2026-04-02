package engine

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// IdentityIndex maps snapshot capture times to their cloud identities.
type IdentityIndex map[time.Time][]asset.CloudIdentity

// BuildIdentityIndex creates an index from sorted snapshots.
func BuildIdentityIndex(snapshots []asset.Snapshot) IdentityIndex {
	idx := make(IdentityIndex, len(snapshots))
	for i := range snapshots {
		idx[snapshots[i].CapturedAt] = snapshots[i].Identities
	}
	return idx
}

// At returns the identities from the snapshot captured at the given time.
// Falls back to the closest snapshot at or before t.
func (idx IdentityIndex) At(t time.Time) []asset.CloudIdentity {
	if ids, ok := idx[t]; ok {
		return ids
	}
	// Fallback: find the closest snapshot at or before t.
	var best time.Time
	for capturedAt := range idx {
		if !capturedAt.After(t) && capturedAt.After(best) {
			best = capturedAt
		}
	}
	if !best.IsZero() {
		return idx[best]
	}
	return nil
}
