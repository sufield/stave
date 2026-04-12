package risk

import (
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// CompoundFinding represents a chain-detected compound risk — multiple
// co-failing controls that together create a risk greater than their sum.
type CompoundFinding struct {
	ChainID           string             `json:"chain"`
	Description       string             `json:"description,omitempty"`
	ControlsFailing   []kernel.ControlID `json:"controls_failing"`
	MissingSafeguards []kernel.ControlID `json:"missing_safeguards,omitempty"`
	CompoundScore     float64            `json:"compound_score"`
	Severity          policy.Severity    `json:"severity"`
	Narrative         string             `json:"narrative"`
	AttackStages      []string           `json:"attack_stages,omitempty"`
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
		var holding []kernel.ControlID
		for _, cid := range chain.ControlIDs {
			if failingIDs[cid] {
				failing = append(failing, cid)
			} else {
				holding = append(holding, cid)
			}
		}

		if len(failing) < chain.EscalationThreshold {
			continue
		}

		// Collect attack stages and compute scope-aware blast multiplier.
		stageSet := make(map[string]bool)
		maxBlast := 1.0
		for _, cid := range failing {
			if ctl, ok := controlLookup[cid]; ok {
				if stage := ctl.AttackStage(); stage != "" {
					stageSet[stage] = true
				}
				mult := scopeAdjustedBlast(ctl)
				if mult > maxBlast {
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
			ChainID:           chain.ID,
			Description:       chain.Description,
			ControlsFailing:   failing,
			MissingSafeguards: holding,
			CompoundScore:     score,
			Severity:          chain.CompoundSeverity,
			Narrative:         narrative,
			AttackStages:      stages,
		})
	}

	return findings
}

// scopeAdjustedBlast computes the effective blast multiplier based on
// the control's declared scope. Account-scoped controls (CloudTrail)
// apply their full multiplier because they blind the entire account.
// Network-scoped controls (VPC Flow Logs) are attenuated because the
// chain may span resources outside that network. Resource-scoped
// controls (S3 logging) are further attenuated because the detection
// gap is local to one resource.
//
// This prevents a single disabled S3 access log from inflating scores
// across unrelated resources — the multiplier is proportional to the
// blast radius scope.
func scopeAdjustedBlast(ctl *policy.ControlDefinition) float64 {
	mult := ctl.BlastMultiplier()
	if mult <= 1.0 {
		return 1.0
	}

	scope := ctl.BlastScope()
	switch scope {
	case "account":
		return mult // Full multiplier — blinds everything
	case "network":
		// Attenuate: network scope may not cover all chain resources.
		// Apply 75% of the excess above 1.0.
		return 1.0 + (mult-1.0)*0.75
	case "resource":
		// Attenuate further: local detection gap.
		// Apply 50% of the excess above 1.0.
		return 1.0 + (mult-1.0)*0.50
	default:
		return mult
	}
}

func buildNarrative(chain *policy.ChainDefinition, failing []kernel.ControlID) string {
	ids := make([]string, len(failing))
	for i, id := range failing {
		ids[i] = string(id)
	}
	return chain.Description + " Failing: " + strings.Join(ids, ", ") + "."
}
