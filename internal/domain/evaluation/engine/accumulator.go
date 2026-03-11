package engine

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
)

// assetIDSet provides a clean interface for unique asset tracking.
type assetIDSet map[asset.ID]struct{}

// Add inserts an ID and returns true if it was not already present.
func (s assetIDSet) Add(id asset.ID) bool {
	if _, ok := s[id]; ok {
		return false
	}
	s[id] = struct{}{}
	return true
}

// Accumulator gathers evaluation artifacts across multiple controls and snapshots.
type Accumulator struct {
	// Collected artifacts
	findings     []evaluation.Finding
	rows         []evaluation.Row
	skippedByCtl []evaluation.SkippedControl
	skippedByAst []asset.SkippedAsset

	// Bookkeeping sets
	seenAssets   assetIDSet
	unsafeAssets assetIDSet
	exemptAssets assetIDSet
}

// NewAccumulator initializes the accumulator.
// assetHint helps pre-allocate internal maps if the total asset count is known.
func NewAccumulator(assetHint int) *Accumulator {
	return &Accumulator{
		seenAssets:   make(assetIDSet, assetHint),
		unsafeAssets: make(assetIDSet, assetHint),
		exemptAssets: make(assetIDSet, assetHint),
	}
}

// TrackExemption records an asset as exempt.
// It returns true if this is the first time this asset has been exempted in this session.
func (a *Accumulator) TrackExemption(id asset.ID) bool {
	return a.exemptAssets.Add(id)
}

func (a *Accumulator) AddSkippedControl(id kernel.ControlID, name, reason string) {
	a.skippedByCtl = append(a.skippedByCtl, evaluation.SkippedControl{
		ControlID:   id,
		ControlName: name,
		Reason:      reason,
	})
}

func (a *Accumulator) AddSkippedAsset(id asset.ID, pattern, reason string) {
	a.skippedByAst = append(a.skippedByAst, asset.SkippedAsset{
		ID:      id,
		Pattern: pattern,
		Reason:  reason,
	})
}

func (a *Accumulator) AddRow(row evaluation.Row) {
	a.rows = append(a.rows, row)
}

func (a *Accumulator) AddFindings(findings []evaluation.Finding) {
	if len(findings) == 0 {
		return
	}
	a.findings = append(a.findings, findings...)
}
