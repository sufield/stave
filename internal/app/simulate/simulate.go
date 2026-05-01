// Package simulate provides what-if counterfactual analysis for
// remediation impact estimation.
package simulate

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/util/sets"
)

// Result holds the simulation output.
type Result struct {
	ControlsFixed     []string      `json:"controls_fixed"`
	ScoreCurrent      float64       `json:"score_current"`
	ScoreSimulated    float64       `json:"score_simulated"`
	ScoreDelta        float64       `json:"score_delta"`
	FindingsRemoved   int           `json:"findings_removed"`
	ChainsDeactivated []ChainChange `json:"chains_deactivated,omitempty"`
}

// ChainChange describes a chain that would deactivate.
type ChainChange struct {
	ChainID  string `json:"chain_id"`
	Severity string `json:"severity"`
	Status   string `json:"status"` // "DEACTIVATED"
}

// Input holds simulation parameters.
type Input struct {
	Findings      []remediation.Finding
	ChainFindings []risk.CompoundFinding
	Chains        []policy.ChainDefinition
	FixControls   []string // control IDs to simulate fixing
	CurrentScore  float64
}

// Run performs the counterfactual simulation.
func Run(input Input) *Result {
	fixSet := sets.New[string](input.FixControls...)

	// Count findings that would be removed.
	removed := 0
	for i := range input.Findings {
		if fixSet.Contains(string(input.Findings[i].ControlID)) {
			removed++
		}
	}

	// Check which chains would deactivate.
	// A chain deactivates when any member control is fixed and
	// the remaining failures drop below the escalation threshold.
	var deactivated []ChainChange
	for i := range input.ChainFindings {
		cf := &input.ChainFindings[i]
		// Count remaining failing members.
		remainingFailing := 0
		for _, cid := range cf.ControlsFailing {
			if !fixSet.Contains(string(cid)) {
				remainingFailing++
			}
		}
		// Find the chain definition to get the threshold.
		for j := range input.Chains {
			ch := &input.Chains[j]
			if ch.ID == cf.ChainID && remainingFailing < ch.EscalationThreshold {
				deactivated = append(deactivated, ChainChange{
					ChainID:  string(ch.ID),
					Severity: ch.CompoundSeverity.String(),
					Status:   "DEACTIVATED",
				})
				break
			}
		}
	}

	// Estimate score delta (simplified: proportional to findings removed).
	totalFindings := len(input.Findings)
	simScore := input.CurrentScore
	if totalFindings > 0 {
		improvementRatio := float64(removed) / float64(totalFindings)
		maxImprovement := 100.0 - input.CurrentScore
		simScore = input.CurrentScore + maxImprovement*improvementRatio*0.6
	}
	// Chain deactivation bonus.
	for range deactivated {
		simScore += 2.0 // each deactivated chain improves score
	}
	if simScore > 100 {
		simScore = 100
	}

	return &Result{
		ControlsFixed:     input.FixControls,
		ScoreCurrent:      input.CurrentScore,
		ScoreSimulated:    simScore,
		ScoreDelta:        simScore - input.CurrentScore,
		FindingsRemoved:   removed,
		ChainsDeactivated: deactivated,
	}
}
