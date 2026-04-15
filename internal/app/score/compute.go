// Package score computes the 0-100 security posture score.
package score

import (
	"math"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
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

// SeverityDetail holds per-dimension detail for the severity component.
type SeverityDetail struct {
	FailingFindings int     `json:"failing_findings"`  // number of failing controls (violations)
	TotalEvaluated  int     `json:"total_evaluated"`   // total controls evaluated (pass + fail); 0 if unknown
	MaxRiskExposure float64 `json:"max_risk_exposure"`
	ActualExposure  float64 `json:"actual_exposure"`
}

// SLADetail holds per-dimension detail for the SLA component.
type SLADetail struct {
	FindingsWithSLA    int     `json:"findings_with_sla"`
	FindingsBreached   int     `json:"findings_breached"`
	BreachRatePercent  float64 `json:"breach_rate_percent"`
}

// ChainDetail holds per-dimension detail for the chain component.
type ChainDetail struct {
	TotalChains       int     `json:"total_chains"`
	ActiveChains      int     `json:"active_chains"`
	MaxChainWeight    float64 `json:"max_chain_weight"`
	ActiveChainWeight float64 `json:"active_chain_weight"`
}

// CoverageDetail holds per-dimension detail for the coverage component.
type CoverageDetail struct {
	Framework              string  `json:"framework,omitempty"`
	RequirementsSatisfied  int     `json:"requirements_satisfied"`
	RequirementsTotal      int     `json:"requirements_total"`
	CoveragePercent        float64 `json:"coverage_percent"`
}

// Component holds a single score dimension.
type Component struct {
	SubScore        float64 `json:"sub_score"`
	Weight          float64 `json:"weight"`
	Contribution    float64 `json:"contribution"`
	MaxContribution float64 `json:"max_contribution"`
}

// SeverityComponent extends Component with severity-specific detail.
type SeverityComponent struct {
	Component
	Detail SeverityDetail `json:"detail"`
}

// SLAComponent extends Component with SLA-specific detail.
type SLAComponent struct {
	Component
	Detail SLADetail `json:"detail"`
}

// ChainComponent extends Component with chain-specific detail.
type ChainComponent struct {
	Component
	Detail ChainDetail `json:"detail"`
}

// CoverageComponent extends Component with coverage-specific detail.
type CoverageComponent struct {
	Component
	Detail CoverageDetail `json:"detail"`
}

// Result is the complete posture score output.
type Result struct {
	Score       float64           `json:"score"`
	ScoreInt    int               `json:"score_int"`
	RubricBand  string            `json:"rubric_band"`
	RubricDesc  string            `json:"rubric_description"`
	Severity    SeverityComponent `json:"severity"`
	SLA         SLAComponent      `json:"sla"`
	Chain       ChainComponent    `json:"chain"`
	Coverage    CoverageComponent `json:"coverage"`
	WeightsUsed Weights           `json:"weights_used"`
}

// ApproximateTotalChains is the approximate number of chain definitions in the
// built-in catalog. Used as the denominator for ChainScore when ChainDefs is
// not explicitly provided.
const ApproximateTotalChains = 50

// Input holds data for score computation.
type Input struct {
	Findings          []evaluation.Finding
	TotalControls     int // total controls evaluated (pass + fail); 0 means use violations as denominator
	ChainFindings     []risk.CompoundFinding
	ChainDefs         int // total threat chain patterns in the YAML catalog (for max weight denominator); use ApproximateTotalChains when count is unknown
	SLABreached       int
	SLATotal          int
	CoveragePct       float64 // 0-100 from compliance profile
	CoverageSatisfied int     // number of requirements satisfied
	CoverageTotal     int     // total requirements in profile
	CoverageFramework string  // framework name for detail output
	HasSLA            bool
	HasCoverage       bool
	Weights           Weights
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
	// MaxRiskExposure includes passing controls when TotalControls is provided.
	// When TotalControls is zero, we use violation-only mode (violation rate).
	var maxExposure, actualExposure float64
	failingCount := 0
	for i := range input.Findings {
		sev := input.Findings[i].ControlSeverity
		sw := severityWeight[sev]
		if sw == 0 {
			sw = 1.0
		}
		actualExposure += sw
		failingCount++
	}
	// If TotalControls is given, compute the theoretical max as if all controls
	// are evaluated at the mean weight (medium = 2.0), adjusted for actual
	// violations' severity. This gives the denominator that makes fixing a
	// violation always increase the score.
	if input.TotalControls > 0 {
		passingCount := input.TotalControls - len(input.Findings)
		if passingCount < 0 {
			// More violations reported than TotalControls — data integrity issue.
			// Clamp to zero; all controls are treated as failing.
			passingCount = 0
		}
		// Passing controls contribute medium-severity weight (2.0) to the denominator.
		// Medium is chosen as a neutral baseline: it lies between the extremes of
		// critical (10.0) and low (1.0), preserving the monotone property (fixing
		// any violation reduces ActualExposure while MaxExposure stays constant)
		// without over- or under-weighting the passing catalog.
		maxExposure = actualExposure + float64(passingCount)*severityWeight[policy.SeverityMedium]
	} else {
		// Violation-only mode: MaxRiskExposure = ActualExposure.
		// SeverityScore = 1.0 when no violations, 0.0 when violations exist.
		maxExposure = actualExposure
	}
	sevScore := 1.0
	if maxExposure > 0 {
		sevScore = 1.0 - (actualExposure / maxExposure)
	}

	// SLA score.
	slaScore := 1.0
	slaBreachRate := 0.0
	if input.HasSLA && input.SLATotal > 0 {
		slaScore = 1.0 - (float64(input.SLABreached) / float64(input.SLATotal))
		slaBreachRate = float64(input.SLABreached) / float64(input.SLATotal) * 100
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
	covReqsSatisfied := 0
	covReqsTotal := 0
	covPct := 0.0
	if input.HasCoverage {
		covScore = input.CoveragePct / 100.0
		covPct = input.CoveragePct
		covReqsTotal = input.CoverageTotal
		covReqsSatisfied = input.CoverageSatisfied
	}

	// Weighted sum.
	total := w.Severity*sevScore + w.SLA*slaScore + w.Chain*chainScore + w.Coverage*covScore
	finalScore := math.Round(total*1000) / 10 // one decimal place

	band, desc := rubric(finalScore)

	sev := SeverityComponent{
		Component: Component{SubScore: sevScore, Weight: w.Severity,
			Contribution: w.Severity * sevScore * 100, MaxContribution: w.Severity * 100},
		Detail: SeverityDetail{
			FailingFindings: failingCount,
			TotalEvaluated:  input.TotalControls,
			MaxRiskExposure: maxExposure,
			ActualExposure:  actualExposure,
		},
	}
	sla := SLAComponent{
		Component: Component{SubScore: slaScore, Weight: w.SLA,
			Contribution: w.SLA * slaScore * 100, MaxContribution: w.SLA * 100},
		Detail: SLADetail{
			FindingsWithSLA:   input.SLATotal,
			FindingsBreached:  input.SLABreached,
			BreachRatePercent: slaBreachRate,
		},
	}
	chain := ChainComponent{
		Component: Component{SubScore: chainScore, Weight: w.Chain,
			Contribution: w.Chain * chainScore * 100, MaxContribution: w.Chain * 100},
		Detail: ChainDetail{
			TotalChains:       input.ChainDefs,
			ActiveChains:      len(input.ChainFindings),
			MaxChainWeight:    maxChainW,
			ActiveChainWeight: activeChainW,
		},
	}
	coverage := CoverageComponent{
		Component: Component{SubScore: covScore, Weight: w.Coverage,
			Contribution: w.Coverage * covScore * 100, MaxContribution: w.Coverage * 100},
		Detail: CoverageDetail{
			Framework:             input.CoverageFramework,
			RequirementsSatisfied: covReqsSatisfied,
			RequirementsTotal:     covReqsTotal,
			CoveragePercent:       covPct,
		},
	}

	return Result{
		Score:       finalScore,
		ScoreInt:    int(finalScore),
		RubricBand:  band,
		RubricDesc:  desc,
		Severity:    sev,
		SLA:         sla,
		Chain:       chain,
		Coverage:    coverage,
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

func findingFailing(f *evaluation.Finding) bool {
	// A finding in the findings array is always failing (violations only).
	return true
}
