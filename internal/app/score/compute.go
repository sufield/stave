// Package score computes the 0-100 security posture score.
package score

import (
	"math"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

// Weights controls the relative importance of each score dimension.
type Weights struct {
	Severity float64 `json:"severity"`
	SLA      float64 `json:"sla"`
	Chain    float64 `json:"chain"`
	Coverage float64 `json:"coverage"`
}

// DefaultWeights returns the standard weight distribution.
func DefaultWeights() Weights {
	return Weights{Severity: 0.45, SLA: 0.25, Chain: 0.20, Coverage: 0.10}
}

// Component holds a single score dimension.
type Component struct {
	SubScore        float64 `json:"sub_score"`
	Weight          float64 `json:"weight"`
	Contribution    float64 `json:"contribution"`
	MaxContribution float64 `json:"max_contribution"`
}

// Result is the complete posture score output.
type Result struct {
	Score       float64   `json:"score"`
	ScoreInt    int       `json:"score_int"`
	RubricBand  string    `json:"rubric_band"`
	RubricDesc  string    `json:"rubric_description"`
	Severity    Component `json:"severity"`
	SLA         Component `json:"sla"`
	Chain       Component `json:"chain"`
	Coverage    Component `json:"coverage"`
	WeightsUsed Weights   `json:"weights_used"`
}

// Input holds data for score computation.
type Input struct {
	Findings      []remediation.Finding
	ChainFindings []risk.CompoundFinding
	ChainDefs     int // total chain definitions (for max weight)
	SLABreached   int
	SLATotal      int
	CoveragePct   float64 // 0-100 from compliance profile
	HasSLA        bool
	HasCoverage   bool
	Weights       Weights
}

var severityWeight = map[policy.Severity]float64{
	policy.SeverityCritical: 10.0,
	policy.SeverityHigh:     4.0,
	policy.SeverityMedium:   2.0,
	policy.SeverityLow:      1.0,
}

var chainWeight = map[policy.Severity]float64{
	policy.SeverityCritical: 10.0,
	policy.SeverityHigh:     4.0,
	policy.SeverityMedium:   2.0,
}

// Compute produces a posture score from assessment data.
func Compute(input Input) Result {
	w := input.Weights

	// Severity score.
	var maxExposure, actualExposure float64
	for i := range input.Findings {
		sev := input.Findings[i].ControlSeverity
		sw := severityWeight[sev]
		if sw == 0 {
			sw = 1.0
		}
		maxExposure += sw
		if findingFailing(&input.Findings[i]) {
			actualExposure += sw
		}
	}
	sevScore := 1.0
	if maxExposure > 0 {
		sevScore = 1.0 - (actualExposure / maxExposure)
	}

	// SLA score.
	slaScore := 1.0
	if input.HasSLA && input.SLATotal > 0 {
		slaScore = 1.0 - (float64(input.SLABreached) / float64(input.SLATotal))
	}

	// Chain score.
	var maxChainW, activeChainW float64
	if input.ChainDefs > 0 {
		// Approximate max: assume all chains are critical.
		maxChainW = float64(input.ChainDefs) * 10.0
	}
	for i := range input.ChainFindings {
		cw := chainWeight[input.ChainFindings[i].Severity]
		if cw == 0 {
			cw = 2.0
		}
		activeChainW += cw
	}
	chainScore := 1.0
	if maxChainW > 0 {
		chainScore = 1.0 - (activeChainW / maxChainW)
		if chainScore < 0 {
			chainScore = 0
		}
	}

	// Coverage score.
	covScore := 1.0
	if input.HasCoverage {
		covScore = input.CoveragePct / 100.0
	}

	// Weighted sum.
	total := w.Severity*sevScore + w.SLA*slaScore + w.Chain*chainScore + w.Coverage*covScore
	finalScore := math.Round(total*1000) / 10 // one decimal place

	band, desc := rubric(finalScore)

	return Result{
		Score:      finalScore,
		ScoreInt:   int(finalScore),
		RubricBand: band,
		RubricDesc: desc,
		Severity: Component{
			SubScore: sevScore, Weight: w.Severity,
			Contribution: w.Severity * sevScore * 100, MaxContribution: w.Severity * 100,
		},
		SLA: Component{
			SubScore: slaScore, Weight: w.SLA,
			Contribution: w.SLA * slaScore * 100, MaxContribution: w.SLA * 100,
		},
		Chain: Component{
			SubScore: chainScore, Weight: w.Chain,
			Contribution: w.Chain * chainScore * 100, MaxContribution: w.Chain * 100,
		},
		Coverage: Component{
			SubScore: covScore, Weight: w.Coverage,
			Contribution: w.Coverage * covScore * 100, MaxContribution: w.Coverage * 100,
		},
		WeightsUsed: w,
	}
}

func rubric(score float64) (string, string) {
	switch {
	case score >= 90:
		return "strong", "No critical findings failing. No SLA breaches. No active compound chains."
	case score >= 75:
		return "adequate", "No critical SLA breaches. Fewer than 2 active chains."
	case score >= 60:
		return "needs_attention", "Critical findings present or SLA breach rate > 10%."
	case score >= 40:
		return "at_risk", "Multiple critical findings breaching SLA. Active compound chains."
	default:
		return "critical", "Widespread critical SLA breaches. Immediate remediation required."
	}
}

func findingFailing(f *remediation.Finding) bool {
	// A finding in the findings array is always failing (violations only).
	return true
}
