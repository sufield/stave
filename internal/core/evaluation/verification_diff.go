package evaluation

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// VerificationDiff captures the delta between two evaluation runs.
// Used primarily in "verify" workflows to confirm remediation success.
type VerificationDiff struct {
	Resolved   []Finding `json:"resolved"`
	Remaining  []Finding `json:"remaining"`
	Introduced []Finding `json:"introduced"`
}

// findingKey provides a unique identifier for a finding instance.
type findingKey struct {
	controlID kernel.ControlID
	assetID   asset.ID
}

// CompareVerificationFindings identifies resolved, remaining, and introduced findings.
// The resulting slices are sorted deterministically via SortFindings.
func CompareVerificationFindings(before, after []Finding) VerificationDiff {
	// 1. Build maps for O(1) lookups.
	// Capacity hints reduce re-allocations for large data sets.
	beforeMap := make(map[findingKey]Finding, len(before))
	for i := range before {
		f := &before[i]
		beforeMap[findingKey{f.ControlID, f.AssetID}] = *f
	}

	afterMap := make(map[findingKey]Finding, len(after))
	for i := range after {
		f := &after[i]
		afterMap[findingKey{f.ControlID, f.AssetID}] = *f
	}

	diff := VerificationDiff{
		Resolved:   make([]Finding, 0),
		Remaining:  make([]Finding, 0),
		Introduced: make([]Finding, 0),
	}

	// 2. Identify Resolved and Remaining
	for key := range beforeMap {
		f := beforeMap[key]
		if _, exists := afterMap[key]; exists {
			diff.Remaining = append(diff.Remaining, f)
		} else {
			diff.Resolved = append(diff.Resolved, f)
		}
	}

	// 3. Identify Introduced (New)
	for key := range afterMap {
		f := afterMap[key]
		if _, exists := beforeMap[key]; !exists {
			diff.Introduced = append(diff.Introduced, f)
		}
	}

	// 4. Sort results for deterministic reporting
	SortFindings(diff.Resolved)
	SortFindings(diff.Remaining)
	SortFindings(diff.Introduced)

	return diff
}
