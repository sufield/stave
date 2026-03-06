package pruner

import "time"

// Criteria defines pruning selection thresholds.
type Criteria struct {
	Now       time.Time
	OlderThan time.Duration
	KeepMin   int
}

// Candidate is a snapshot item considered by pruning policy.
type Candidate struct {
	Index      int
	CapturedAt time.Time
}

// PlanPrune selects candidates older than the cutoff while preserving KeepMin floor.
// Input order is preserved for returned candidates.
func PlanPrune(items []Candidate, criteria Criteria) []Candidate {
	cutoff := criteria.Now.Add(-criteria.OlderThan)
	candidates := make([]Candidate, 0, len(items))
	for _, item := range items {
		if item.CapturedAt.Before(cutoff) {
			candidates = append(candidates, item)
		}
	}

	maxDeletions := max(len(items)-criteria.KeepMin, 0)
	if len(candidates) > maxDeletions {
		candidates = candidates[:maxDeletions]
	}
	return candidates
}
