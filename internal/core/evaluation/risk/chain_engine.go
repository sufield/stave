package risk

import (
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// CompoundFinding represents a chain-detected compound risk — multiple
// co-failing controls that together create a risk greater than their sum.
type CompoundFinding struct {
	ChainID         string             `json:"chain"`
	Description     string             `json:"description,omitempty"`
	ControlsFailing []kernel.ControlID `json:"controls_failing"`
	CompoundScore   float64            `json:"compound_score"`
	Severity        policy.Severity    `json:"severity"`
	Narrative       string             `json:"narrative"`
	AttackStages    []string           `json:"attack_stages,omitempty"`
}

// DetectChains matches a set of failing control IDs against chain
// definitions and returns compound findings for chains whose escalation
// threshold is met.
//
// failingIDs is the set of control IDs that have violations.
// chains is the catalog of chain definitions to check.
// controlLookup maps control IDs to their definitions (for attack stage).
func DetectChains(
	failingIDs map[kernel.ControlID]bool,
	chains []policy.ChainDefinition,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
) []CompoundFinding {
	var findings []CompoundFinding

	for i := range chains {
		chain := &chains[i]
		var failing []kernel.ControlID
		for _, cid := range chain.ControlIDs {
			if failingIDs[cid] {
				failing = append(failing, cid)
			}
		}

		if len(failing) < chain.EscalationThreshold {
			continue
		}

		// Collect attack stages from failing controls.
		stageSet := make(map[string]bool)
		maxBlast := 1.0
		for _, cid := range failing {
			if ctl, ok := controlLookup[cid]; ok {
				if stage := ctl.AttackStage(); stage != "" {
					stageSet[stage] = true
				}
				if mult := ctl.BlastMultiplier(); mult > maxBlast {
					maxBlast = mult
				}
			}
		}

		var stages []string
		for s := range stageSet {
			stages = append(stages, s)
		}

		escalation := ChainEscalation(len(failing))
		// Use a base score of 10 (default) × escalation × blast for chains
		// without per-finding environmental scores.
		score := Compound(10.0, escalation, maxBlast)

		narrative := buildNarrative(chain, failing)

		findings = append(findings, CompoundFinding{
			ChainID:         chain.ID,
			Description:     chain.Description,
			ControlsFailing: failing,
			CompoundScore:   score,
			Severity:        chain.CompoundSeverity,
			Narrative:       narrative,
			AttackStages:    stages,
		})
	}

	return findings
}

func buildNarrative(chain *policy.ChainDefinition, failing []kernel.ControlID) string {
	ids := make([]string, len(failing))
	for i, id := range failing {
		ids[i] = string(id)
	}
	return chain.Description + " Failing: " + strings.Join(ids, ", ") + "."
}
