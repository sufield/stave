package evaluation

import (
	"cmp"
	"slices"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
)

// BaselineEntry represents a single finding captured in a baseline snapshot.
type BaselineEntry struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	AssetID     asset.ID         `json:"asset_id"`
	AssetType   kernel.AssetType `json:"asset_type"`
}

// BaselineEntryKey is a composite key for baseline entry comparison and deduplication.
type BaselineEntryKey struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// Key returns a typed composite key for comparison and deduplication.
func (e BaselineEntry) Key() BaselineEntryKey {
	return BaselineEntryKey{ControlID: e.ControlID, AssetID: e.AssetID}
}

// Baseline represents the persistent state of known/accepted violations.
type Baseline struct {
	SchemaVersion    kernel.Schema     `json:"schema_version"`
	Kind             kernel.OutputKind `json:"kind"`
	CreatedAt        time.Time         `json:"created_at"`
	SourceEvaluation string            `json:"source_evaluation"`
	Findings         []BaselineEntry   `json:"findings"`
}

// BaselineComparisonSummary provides aggregate counts for a baseline check.
type BaselineComparisonSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

// BaselineComparison represents the result of checking current findings against a baseline.
type BaselineComparison struct {
	SchemaVersion kernel.Schema             `json:"schema_version"`
	Kind          kernel.OutputKind         `json:"kind"`
	CheckedAt     time.Time                 `json:"checked_at"`
	BaselineFile  string                    `json:"baseline_file"`
	Evaluation    string                    `json:"evaluation"`
	Summary       BaselineComparisonSummary `json:"summary"`
	New           []BaselineEntry           `json:"new"`
	Resolved      []BaselineEntry           `json:"resolved"`
}

// BaselineComparisonResult holds the diff output between two sets of entries.
type BaselineComparisonResult struct {
	New      []BaselineEntry
	Resolved []BaselineEntry
}

// HasNewFindings reports whether the comparison found new violations.
func (r BaselineComparisonResult) HasNewFindings() bool {
	return len(r.New) > 0
}

// BaselineEntryFromFinding converts a detailed Finding into a simplified BaselineEntry.
func BaselineEntryFromFinding(f Finding) BaselineEntry {
	return BaselineEntry{
		ControlID:   f.ControlID,
		ControlName: f.ControlName,
		AssetID:     f.AssetID,
		AssetType:   f.AssetType,
	}
}

// CompareBaseline compares baseline and current entries, identifying introduced (new)
// and resolved (removed) violations.
func CompareBaseline(baseEntries, curEntries []BaselineEntry) BaselineComparisonResult {
	// Pre-allocate maps for lookups to ensure O(N+M) complexity
	baseMap := make(map[BaselineEntryKey]BaselineEntry, len(baseEntries))
	for _, b := range baseEntries {
		baseMap[b.Key()] = b
	}

	curMap := make(map[BaselineEntryKey]BaselineEntry, len(curEntries))
	for _, c := range curEntries {
		curMap[c.Key()] = c
	}

	var newFindings, resolvedFindings []BaselineEntry

	// Find items in current that are not in base (New)
	for key, entry := range curMap {
		if _, exists := baseMap[key]; !exists {
			newFindings = append(newFindings, entry)
		}
	}

	// Find items in base that are not in current (Resolved)
	for key, entry := range baseMap {
		if _, exists := curMap[key]; !exists {
			resolvedFindings = append(resolvedFindings, entry)
		}
	}

	SortBaselineEntries(newFindings)
	SortBaselineEntries(resolvedFindings)

	return BaselineComparisonResult{
		New:      newFindings,
		Resolved: resolvedFindings,
	}
}

// SortBaselineEntries sorts entries deterministically by ControlID then AssetID.
func SortBaselineEntries(entries []BaselineEntry) {
	slices.SortFunc(entries, func(a, b BaselineEntry) int {
		return cmp.Or(
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.AssetID, b.AssetID),
		)
	})
}
