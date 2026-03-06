package evaluation

import (
	"sort"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/fp"
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

// Baseline is the baseline.v0.1 output file.
type Baseline struct {
	SchemaVersion    kernel.Schema   `json:"schema_version"`
	Kind             string          `json:"kind"`
	CreatedAt        time.Time       `json:"created_at"`
	SourceEvaluation string          `json:"source_evaluation"`
	Findings         []BaselineEntry `json:"findings"`
}

// BaselineComparisonSummary provides aggregate counts for a baseline check.
type BaselineComparisonSummary struct {
	BaselineFindings int `json:"baseline_findings"`
	CurrentFindings  int `json:"current_findings"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

// BaselineComparison is the baseline_check output.
type BaselineComparison struct {
	SchemaVersion kernel.Schema             `json:"schema_version"`
	Kind          string                    `json:"kind"`
	CheckedAt     time.Time                 `json:"checked_at"`
	BaselineFile  string                    `json:"baseline_file"`
	Evaluation    string                    `json:"evaluation"`
	Summary       BaselineComparisonSummary `json:"summary"`
	New           []BaselineEntry           `json:"new"`
	Resolved      []BaselineEntry           `json:"resolved"`
}

// BaselineEntryFromFinding creates a BaselineEntry from a Finding.
func BaselineEntryFromFinding(f Finding) BaselineEntry {
	return BaselineEntry{
		ControlID:   f.ControlID,
		ControlName: f.ControlName,
		AssetID:     f.AssetID,
		AssetType:   f.AssetType,
	}
}

// BaselineComparisonResult holds the output of a baseline comparison.
type BaselineComparisonResult struct {
	New      []BaselineEntry
	Resolved []BaselineEntry
}

// HasNewFindings reports whether the comparison found new violations.
func (r BaselineComparisonResult) HasNewFindings() bool {
	return len(r.New) > 0
}

// CompareBaseline compares base and current entries, returning newly introduced and resolved entries.
func CompareBaseline(base, current []BaselineEntry) BaselineComparisonResult {
	baseSet := fp.ToMap(base, BaselineEntry.Key)
	curSet := fp.ToMap(current, BaselineEntry.Key)

	var newEntries, resolved []BaselineEntry
	for k, e := range curSet {
		if _, ok := baseSet[k]; !ok {
			newEntries = append(newEntries, e)
		}
	}
	for k, e := range baseSet {
		if _, ok := curSet[k]; !ok {
			resolved = append(resolved, e)
		}
	}
	SortBaselineEntries(newEntries)
	SortBaselineEntries(resolved)
	return BaselineComparisonResult{New: newEntries, Resolved: resolved}
}

// SortBaselineEntries sorts entries by control ID then asset ID.
func SortBaselineEntries(entries []BaselineEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ControlID != entries[j].ControlID {
			return entries[i].ControlID < entries[j].ControlID
		}
		return entries[i].AssetID < entries[j].AssetID
	})
}
