package retention

import (
	"slices"
	"time"
)

// Criteria defines the boundaries for a pruning operation.
type Criteria struct {
	Now       time.Time     // Reference time for age calculation
	OlderThan time.Duration // Age threshold for pruning eligibility
	KeepMin   int           // Absolute minimum number of items to retain
}

// Candidate is a snapshot item considered by pruning policy.
// Index maps back to the caller's original slice for post-selection lookups.
type Candidate struct {
	Index      int
	CapturedAt time.Time
}

// PlanPrune selects candidates older than the cutoff while preserving the
// KeepMin safety floor.
//
// Items MUST be sorted by CapturedAt ascending (oldest first). The function
// exits early once it encounters an item newer than the cutoff, and the
// KeepMin cap trims the oldest candidates.
//
// When OlderThan is zero the cutoff equals Now, selecting all items for
// pruning (subject to KeepMin).
//
// Returns a cloned slice to prevent the caller from accidentally modifying
// the source data via the returned slice header.
func PlanPrune(items []Candidate, criteria Criteria) []Candidate {
	if len(items) <= criteria.KeepMin {
		return nil
	}

	cutoff := criteria.Now.Add(-criteria.OlderThan)

	// Count expired items. Since items are sorted oldest-first, we can
	// stop as soon as we hit one within the retention window.
	expiredCount := 0
	for _, item := range items {
		if !item.CapturedAt.Before(cutoff) {
			break
		}
		expiredCount++
	}

	// Apply the KeepMin safety floor.
	maxPrunable := len(items) - criteria.KeepMin
	toPrune := min(expiredCount, maxPrunable)

	if toPrune <= 0 {
		return nil
	}

	return slices.Clone(items[:toPrune])
}
