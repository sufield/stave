package stave

import (
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// ChainFinding is a detected compound-risk chain — multiple co-failing
// controls that together create a risk greater than the sum of
// individual findings. Emitted when the number of failing controls in
// a chain definition meets the chain's escalation threshold.
//
// This is a trimmed, library-friendly view of the engine's internal
// compound finding. Fields are populated at the library boundary from
// evaluation.ComplianceReport.ChainFindings; the engine's raw shape
// uses string IDs rather than typed primitives.
type ChainFinding struct {
	// ChainID identifies the chain definition (e.g.
	// "privilege_escalation_path"). Typed so consumers can compare
	// directly with ChainMembershipEntry.ChainID without string casts.
	ChainID ChainID

	// Description is the authored chain description from the YAML.
	Description string

	// ControlsFailing lists the controls that fired and contributed to
	// this chain's activation.
	ControlsFailing []ControlID

	// MissingSafeguards lists chain-member controls that did NOT fire.
	// A chain with "3 controls, escalation_threshold: 2" can activate
	// with 2 fired + 1 holding; MissingSafeguards names the holding one.
	MissingSafeguards []ControlID

	// CompoundScore is the chain's priority score after escalation
	// weighting and blast-radius adjustment.
	CompoundScore float64

	// Severity is the chain's declared compound severity, not
	// necessarily equal to any individual member's severity.
	Severity Severity

	// Narrative is a catalog-authored or derived human-readable
	// summary of the chain's attack-path story.
	Narrative string

	// AttackStages is the set of MITRE ATT&CK-aligned stages the
	// failing member controls collectively span, sorted by kill-chain
	// order.
	AttackStages []string
}

// ChainMembershipEntry records that a specific Finding contributes to
// a fired ChainFinding. A Finding on multiple chains has one entry per
// chain. Surfaced on Finding.ChainMembership.
type ChainMembershipEntry struct {
	// ChainID matches a ChainFinding.ChainID in the Assessment.
	ChainID ChainID

	// ChainSeverity is the compound severity of the chain (same value
	// as ChainFinding.Severity for the matching chain).
	ChainSeverity Severity

	// StageSpan is the chain's attack-stage span, copied from the
	// ChainFinding for convenience.
	StageSpan []string

	// Narrative is the chain's human-readable description.
	Narrative string
}

// convertCompoundFinding converts an internal findings.CompoundFinding into
// the library's ChainFinding shape, applying the typed-ChainID
// conversion at the boundary.
func convertCompoundFinding(cf *findings.CompoundFinding) ChainFinding {
	return ChainFinding{
		ChainID:           cf.ChainID,
		Description:       cf.Description,
		ControlsFailing:   cloneControlIDs(cf.ControlsFailing),
		MissingSafeguards: cloneControlIDs(cf.MissingSafeguards),
		CompoundScore:     cf.CompoundScore,
		Severity:          Severity(cf.Severity.String()),
		Narrative:         cf.Narrative,
		AttackStages:      attackStagesToStrings(cf.AttackStages),
	}
}

// convertChainMembership converts an internal evaluation.ChainMembershipEntry
// slice into the library's typed shape.
func convertChainMembership(ms []evaluation.ChainMembershipEntry) []ChainMembershipEntry {
	if len(ms) == 0 {
		return nil
	}
	out := make([]ChainMembershipEntry, len(ms))
	for i, m := range ms {
		out[i] = ChainMembershipEntry{
			ChainID:       m.ChainID,
			ChainSeverity: Severity(m.ChainSeverity.String()),
			StageSpan:     attackStagesToStrings(m.StageSpan),
			Narrative:     m.Narrative,
		}
	}
	return out
}

func cloneControlIDs(in []ControlID) []ControlID {
	if in == nil {
		return nil
	}
	out := make([]ControlID, len(in))
	copy(out, in)
	return out
}

// attackStagesToStrings projects internal kernel.AttackStage values
// onto the library's plain []string surface.
func attackStagesToStrings(in []kernel.AttackStage) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(s)
	}
	return out
}
