// Package score computes the 0-100 security posture score.
package score

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

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

// SeverityDetail holds breakdown data for the severity component.
type SeverityDetail struct {
	TotalFindings   int     `json:"total_findings"`
	FailingFindings int     `json:"failing_findings"`
	MaxRiskExposure float64 `json:"max_risk_exposure"`
	ActualExposure  float64 `json:"actual_exposure"`
}

// SLADetail holds breakdown data for the SLA component.
type SLADetail struct {
	FindingsWithSLA  int     `json:"findings_with_sla"`
	FindingsBreached int     `json:"findings_breached"`
	BreachRatePct    float64 `json:"breach_rate_percent"`
}

// ChainDetail holds breakdown data for the chain component.
type ChainDetail struct {
	TotalChains       int     `json:"total_chains"`
	ActiveChains      int     `json:"active_chains"`
	MaxChainWeight    float64 `json:"max_chain_weight"`
	ActiveChainWeight float64 `json:"active_chain_weight"`
}

// CoverageDetail holds breakdown data for the coverage component.
type CoverageDetail struct {
	Framework             string  `json:"framework,omitempty"`
	RequirementsSatisfied int     `json:"requirements_satisfied"`
	RequirementsTotal     int     `json:"requirements_total"`
	CoveragePct           float64 `json:"coverage_percent"`
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

// TrendPoint captures a single score observation for trend display.
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
}

// Result is the complete posture score output.
type Result struct {
	GeneratedAt time.Time         `json:"generated_at"`
	SnapshotID  string            `json:"snapshot_id,omitempty"`
	Score       float64           `json:"score"`
	ScoreInt    int               `json:"score_int"`
	RubricBand  string            `json:"rubric_band"`
	RubricDesc  string            `json:"rubric_description"`
	Severity    SeverityComponent `json:"severity"`
	SLA         SLAComponent      `json:"sla"`
	Chain       ChainComponent    `json:"chain"`
	Coverage    CoverageComponent `json:"coverage"`
	WeightsUsed Weights           `json:"weights_used"`
	Trend       []TrendPoint      `json:"trend,omitempty"`
}

// Input holds data for score computation.
type Input struct {
	Findings         []remediation.Finding
	ChainFindings    []risk.CompoundFinding
	ChainDefs        int     // total chain definitions count (for detail output)
	MaxChainWeight   float64 // severity-weighted total for all chain definitions; 0 = ChainDefs * 10.0 fallback
	SLABreached      int
	SLATotal         int
	CoveragePct      float64 // 0-100 from compliance profile
	TotalCheckWeight float64 // severity-weighted total of ALL evaluations (pass + fail); 0 = derive from findings
	HasSLA           bool
	HasCoverage      bool
	Weights          Weights
	GeneratedAt      time.Time
	SnapshotID       string
}

// ParseWeights parses a weights override string in the format
// "severity=0.45,sla=0.25,chain=0.20,coverage=0.10".
// Missing keys retain their default value. Returns an error if
// any key is unknown or a value is not a valid float.
func ParseWeights(s string) (Weights, error) {
	w := DefaultWeights()
	if s == "" {
		return w, nil
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return w, fmt.Errorf("invalid weight %q: expected key=value", pair)
		}
		val, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return w, fmt.Errorf("invalid weight value %q: %w", v, err)
		}
		switch strings.TrimSpace(k) {
		case "severity":
			w.Severity = val
		case "sla":
			w.SLA = val
		case "chain":
			w.Chain = val
		case "coverage":
			w.Coverage = val
		default:
			return w, fmt.Errorf("unknown weight key %q", k)
		}
	}
	return w, nil
}

var severityWeight = map[policy.Severity]float64{
	policy.SeverityCritical: 10.0,
	policy.SeverityHigh:     4.0,
	policy.SeverityMedium:   2.0,
	policy.SeverityLow:      1.0,
}

// SeverityWeightFor returns the score weight for a given severity level.
func SeverityWeightFor(sev policy.Severity) float64 {
	if w, ok := severityWeight[sev]; ok {
		return w
	}
	return 1.0
}

var chainWeight = map[policy.Severity]float64{
	policy.SeverityCritical: 10.0,
	policy.SeverityHigh:     4.0,
	policy.SeverityMedium:   2.0,
}

// ChainMaxWeight computes the severity-weighted maximum chain weight
// from actual chain definitions. Each chain contributes its
// CompoundSeverity weight (critical=10, high=4, medium=2).
func ChainMaxWeight(chains []policy.ChainDefinition) float64 {
	var total float64
	for i := range chains {
		cw := chainWeight[chains[i].CompoundSeverity]
		if cw == 0 {
			cw = 2.0 // default for unknown severity
		}
		total += cw
	}
	return total
}

// Compute produces a posture score from assessment data.
func Compute(input Input) Result {
	w := input.Weights

	genAt := input.GeneratedAt

	// Severity score.
	// actualExposure = sum of severity weights for all FAILING findings.
	// maxExposure = TotalCheckWeight if provided (includes passing), else
	// falls back to sum of violation weights.
	var actualExposure float64
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
	maxExposure := input.TotalCheckWeight
	if maxExposure <= 0 {
		maxExposure = actualExposure
	}
	sevScore := 1.0
	if maxExposure > 0 {
		sevScore = 1.0 - (actualExposure / maxExposure)
	}

	// SLA score.
	slaScore := 1.0
	var breachRatePct float64
	if input.HasSLA && input.SLATotal > 0 {
		slaScore = 1.0 - (float64(input.SLABreached) / float64(input.SLATotal))
		breachRatePct = float64(input.SLABreached) / float64(input.SLATotal) * 100
	}

	// Chain score.
	var maxChainW, activeChainW float64
	if input.MaxChainWeight > 0 {
		maxChainW = input.MaxChainWeight
	} else if input.ChainDefs > 0 {
		// Fallback: assume all chains are critical when actual weights unavailable.
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
		GeneratedAt: genAt,
		SnapshotID:  input.SnapshotID,
		Score:       finalScore,
		ScoreInt:    int(finalScore),
		RubricBand:  band,
		RubricDesc:  desc,
		Severity: SeverityComponent{
			Component: Component{
				SubScore: sevScore, Weight: w.Severity,
				Contribution: w.Severity * sevScore * 100, MaxContribution: w.Severity * 100,
			},
			Detail: SeverityDetail{
				TotalFindings:   len(input.Findings),
				FailingFindings: failingCount,
				MaxRiskExposure: maxExposure,
				ActualExposure:  actualExposure,
			},
		},
		SLA: SLAComponent{
			Component: Component{
				SubScore: slaScore, Weight: w.SLA,
				Contribution: w.SLA * slaScore * 100, MaxContribution: w.SLA * 100,
			},
			Detail: SLADetail{
				FindingsWithSLA:  input.SLATotal,
				FindingsBreached: input.SLABreached,
				BreachRatePct:    breachRatePct,
			},
		},
		Chain: ChainComponent{
			Component: Component{
				SubScore: chainScore, Weight: w.Chain,
				Contribution: w.Chain * chainScore * 100, MaxContribution: w.Chain * 100,
			},
			Detail: ChainDetail{
				TotalChains:       input.ChainDefs,
				ActiveChains:      len(input.ChainFindings),
				MaxChainWeight:    maxChainW,
				ActiveChainWeight: activeChainW,
			},
		},
		Coverage: CoverageComponent{
			Component: Component{
				SubScore: covScore, Weight: w.Coverage,
				Contribution: w.Coverage * covScore * 100, MaxContribution: w.Coverage * 100,
			},
			Detail: CoverageDetail{
				CoveragePct: input.CoveragePct,
			},
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
