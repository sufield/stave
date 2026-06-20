package engine

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// identityEntry pairs a timestamp with an identity set.
// Using a slice of entries instead of a map avoids time.Time key
// collisions when multiple snapshots share the same CapturedAt.
type identityEntry struct {
	capturedAt time.Time
	identities []asset.CloudIdentity
}

// IdentityIndex maps snapshot capture times to their cloud identities.
// Uses a sorted slice of entries to avoid map key collisions and
// enable O(log S) fallback lookup via binary search.
type IdentityIndex struct {
	entries []identityEntry
}

// BuildIdentityIndex creates an index from snapshots.
// Each snapshot gets its own entry — no collision even when timestamps match.
func BuildIdentityIndex(snapshots []asset.Snapshot) IdentityIndex {
	idx := IdentityIndex{
		entries: make([]identityEntry, len(snapshots)),
	}
	for i := range snapshots {
		idx.entries[i] = identityEntry{
			capturedAt: snapshots[i].CapturedAt,
			identities: snapshots[i].Identities,
		}
	}
	slices.SortFunc(idx.entries, func(a, b identityEntry) int {
		return a.capturedAt.Compare(b.capturedAt)
	})
	return idx
}

// At returns the identities from the snapshot captured at the given time.
// Falls back to the closest snapshot at or before t using O(log S) binary search.
func (idx IdentityIndex) At(t time.Time) []asset.CloudIdentity {
	if len(idx.entries) == 0 {
		return nil
	}

	// Binary search for the closest entry at or before t.
	i, found := slices.BinarySearchFunc(idx.entries, t, func(e identityEntry, target time.Time) int {
		return e.capturedAt.Compare(target)
	})

	if found && i < len(idx.entries) {
		// Exact match found at index i.
		// Since there may be multiple entries with the same timestamp, gather all of them.
		matchTime := idx.entries[i].capturedAt
		return idx.mergeIdentitiesAt(i, matchTime)
	}

	// i is the insertion point — the entry before it is the closest at-or-before.
	if i > 0 {
		matchTime := idx.entries[i-1].capturedAt
		return idx.mergeIdentitiesAt(i-1, matchTime)
	}
	return nil
}

// mergeIdentitiesAt gathers and merges all identities from entries sharing matchTime,
// starting the scan from a known index idxRef.
func (idx IdentityIndex) mergeIdentitiesAt(idxRef int, matchTime time.Time) []asset.CloudIdentity {
	start := idxRef
	for start > 0 && idx.entries[start-1].capturedAt.Equal(matchTime) {
		start--
	}
	end := idxRef
	for end < len(idx.entries)-1 && idx.entries[end+1].capturedAt.Equal(matchTime) {
		end++
	}

	var merged []asset.CloudIdentity
	for k := start; k <= end; k++ {
		merged = append(merged, idx.entries[k].identities...)
	}
	return merged
}
