package engine

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// IdentityIndex maps snapshot capture times to their cloud identities.
// A sorted timestamp slice enables O(log S) fallback lookup.
type IdentityIndex struct {
	byTime     map[time.Time][]asset.CloudIdentity
	sortedKeys []time.Time
}

// BuildIdentityIndex creates an index from sorted snapshots.
func BuildIdentityIndex(snapshots []asset.Snapshot) IdentityIndex {
	idx := IdentityIndex{
		byTime:     make(map[time.Time][]asset.CloudIdentity, len(snapshots)),
		sortedKeys: make([]time.Time, 0, len(snapshots)),
	}
	for i := range snapshots {
		t := snapshots[i].CapturedAt
		idx.byTime[t] = snapshots[i].Identities
		idx.sortedKeys = append(idx.sortedKeys, t)
	}
	slices.SortFunc(idx.sortedKeys, func(a, b time.Time) int {
		return a.Compare(b)
	})
	return idx
}

// At returns the identities from the snapshot captured at the given time.
// Falls back to the closest snapshot at or before t using O(log S) binary search.
func (idx IdentityIndex) At(t time.Time) []asset.CloudIdentity {
	if ids, ok := idx.byTime[t]; ok {
		return ids
	}
	// Binary search for the closest timestamp at or before t.
	i, _ := slices.BinarySearchFunc(idx.sortedKeys, t, func(key, target time.Time) int {
		return key.Compare(target)
	})
	// i is the insertion point — the entry before it is the closest at-or-before.
	if i > 0 {
		return idx.byTime[idx.sortedKeys[i-1]]
	}
	return nil
}
