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
		return idx.entries[i].identities
	}

	// i is the insertion point — the entry before it is the closest at-or-before.
	if i > 0 {
		return idx.entries[i-1].identities
	}
	return nil
}
