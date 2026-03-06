package engine

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
)

// resourceIDSet tracks a set of resource IDs without the ambiguity of map[string]bool.
type resourceIDSet map[asset.ID]struct{}

func newResourceIDSet() resourceIDSet        { return resourceIDSet{} }
func (s resourceIDSet) add(id asset.ID)      { s[id] = struct{}{} }
func (s resourceIDSet) has(id asset.ID) bool { _, ok := s[id]; return ok }
func (s resourceIDSet) len() int             { return len(s) }

// evaluationAccumulator collects findings, rows, and skip info during evaluation.
type evaluationAccumulator struct {
	findings            []evaluation.Finding
	rows                []evaluation.Row
	skipped             []evaluation.SkippedControl
	skippedResources    []asset.SkippedAsset
	seenResources       resourceIDSet
	unsafeResources     resourceIDSet
	exemptedResourceIDs resourceIDSet
}

func newEvaluationAccumulator() *evaluationAccumulator {
	return &evaluationAccumulator{
		seenResources:       newResourceIDSet(),
		unsafeResources:     newResourceIDSet(),
		exemptedResourceIDs: newResourceIDSet(),
	}
}

func (acc *evaluationAccumulator) isNewExemption(assetID asset.ID) bool {
	return !acc.exemptedResourceIDs.has(assetID)
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
	acc.skippedResources = append(acc.skippedResources, asset.SkippedAsset{
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
