package engine

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
)

// assetIDSet tracks a set of asset IDs without the ambiguity of map[string]bool.
type assetIDSet map[asset.ID]struct{}

func newAssetIDSet() assetIDSet        { return assetIDSet{} }
func (s assetIDSet) add(id asset.ID)      { s[id] = struct{}{} }
func (s assetIDSet) has(id asset.ID) bool { _, ok := s[id]; return ok }
func (s assetIDSet) len() int             { return len(s) }

// evaluationAccumulator collects findings, rows, and skip info during evaluation.
type evaluationAccumulator struct {
	findings            []evaluation.Finding
	rows                []evaluation.Row
	skipped             []evaluation.SkippedControl
	skippedAssets    []asset.SkippedAsset
	seenAssets       assetIDSet
	unsafeAssets     assetIDSet
	exemptedAssetIDs assetIDSet
}

func newEvaluationAccumulator() *evaluationAccumulator {
	return &evaluationAccumulator{
		seenAssets:       newAssetIDSet(),
		unsafeAssets:     newAssetIDSet(),
		exemptedAssetIDs: newAssetIDSet(),
	}
}

func (acc *evaluationAccumulator) isNewExemption(assetID asset.ID) bool {
	return !acc.exemptedAssetIDs.has(assetID)
}

func (acc *evaluationAccumulator) addSkippedControl(
	controlID kernel.ControlID,
	controlName, reason string,
) {
	acc.skipped = append(acc.skipped, evaluation.SkippedControl{
		ControlID:   controlID,
		ControlName: controlName,
		Reason:      reason,
	})
}

func (acc *evaluationAccumulator) addSkippedAsset(assetID asset.ID, pattern, reason string) {
	acc.skippedAssets = append(acc.skippedAssets, asset.SkippedAsset{
		ID:      assetID,
		Pattern: pattern,
		Reason:  reason,
	})
}

func (acc *evaluationAccumulator) addRow(row evaluation.Row) {
	acc.rows = append(acc.rows, row)
}

func (acc *evaluationAccumulator) addFindings(findings []evaluation.Finding) {
	if len(findings) == 0 {
		return
	}
	acc.findings = append(acc.findings, findings...)
}
