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
//
// Both TotalViolations and FailingFindings count entries in the input
// Findings slice — which is itself already filtered to violations
// upstream. The two fields share a value by construction; they exist
// separately so consumers that want "violations seen" and consumers
// that want "violations contributing to the failing-count signal" can
// pick the one matching their semantic. The legacy `total_findings`
// JSON tag is preserved for stable wire-format consumers.
type SeverityDetail struct {
	TotalViolations int     `json:"total_findings"`
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
	for pair := range strings.SplitSeq(s, ",") {
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

// severityResult carries the values produced by computeSeverityScore
// so they can flow through to the Result without re-deriving them.
type severityResult struct {
	subScore       float64
	actualExposure float64
	reportedMax    float64
	failingCount   int
}

// chainResult carries the values from computeChainScore through to
// the Result, mirroring severityResult's shape.
type chainResult struct {
	subScore     float64
	maxWeight    float64
	activeWeight float64
}

// Compute produces a posture score from assessment data.
func Compute(input Input) Result {
	w := input.Weights
	genAt := input.GeneratedAt

	sev := computeSeverityScore(input)
	slaScore, breachRatePct := computeSLAScore(input)
	chain := computeChainScore(input)
	covScore := computeCoverageScore(input)

	// Weighted sum. Each sub-score is in [0, 1] and the weights sum to
	// 1.0 (DefaultWeights enforces this; ParseWeights normalizes), so
	// `total` is also in [0, 1]. The rounding step rescales to the
	// reported 0–100 range with one decimal place: total*1000 lands in
	// [0, 1000], Round() pins to integer tenths-of-a-percent, /10 maps
	// back to [0.0, 100.0].
	total := w.Severity*sev.subScore + w.SLA*slaScore + w.Chain*chain.subScore + w.Coverage*covScore
	finalScore := math.Round(total*1000) / 10

	band, desc := rubric(finalScore)

	// The remaining Result construction reads from the locals above;
	// alias them so the existing field-init block stays unchanged.
	sevScore := sev.subScore
	failingCount := sev.failingCount
	actualExposure := sev.actualExposure
	reportedMaxExposure := sev.reportedMax
	chainScore := chain.subScore
	maxChainW := chain.maxWeight
	activeChainW := chain.activeWeight

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
				TotalViolations: len(input.Findings),
				FailingFindings: failingCount,
				MaxRiskExposure: reportedMaxExposure,
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

// computeSeverityScore turns the failing-finding set into the
// severity sub-score plus the supporting numbers needed for the
// Result detail block.
//
// actualExposure = sum of severity weights for all FAILING findings.
// maxExposure = TotalCheckWeight if provided (includes passing), else
// falls back to a meaningful "average severity" score so a cluster
// with only Low findings doesn't collapse to 0 the way the previous
// "maxExposure = actualExposure" fallback did.
func computeSeverityScore(input Input) severityResult {
	var actualExposure float64
	failingCount := 0
	for i := range input.Findings {
		s := input.Findings[i].ControlSeverity
		sw := severityWeight[s]
		if sw == 0 {
			sw = 1.0
		}
		actualExposure += sw
		failingCount++
	}

	maxExposure := input.TotalCheckWeight
	subScore := 1.0
	switch {
	case maxExposure > 0:
		// Standard path: severity score is 1 - (exposure / max).
		// Clamp below to [0, 1] — TotalCheckWeight under-counting
		// (catalog drift, fixture truncation) used to produce
		// negative scores that displayed as nonsense rubric bands;
		// cap at 0 so a fully-saturated cluster reports the worst
		// score, not below it.
		subScore = 1.0 - (actualExposure / maxExposure)
	case failingCount > 0:
		// Fallback when total-check-weight is unavailable: compute
		// 1 - (avg severity weight / max severity weight). A cluster
		// with only Low findings scores near 0.9; one with all
		// Critical findings scores 0. Still flagged as a fallback
		// shape (TotalCheckWeight==0) so callers can warn that the
		// upstream count is missing.
		avgWeight := actualExposure / float64(failingCount)
		maxSev := severityWeight[policy.SeverityCritical]
		if maxSev > 0 {
			subScore = 1.0 - (avgWeight / maxSev)
		}
	}
	// Clamp to [0, 1] regardless of which branch produced the value
	// — both paths can drift outside the range with adversarial input
	// (negative TotalCheckWeight, severity weights tuned >Critical).
	subScore = math.Max(0, math.Min(1.0, subScore))

	// MaxRiskExposure reported in the result reflects the value
	// actually used in the score calc — including the fallback.
	reportedMax := maxExposure
	if reportedMax <= 0 {
		reportedMax = actualExposure
	}
	return severityResult{
		subScore:       subScore,
		actualExposure: actualExposure,
		reportedMax:    reportedMax,
		failingCount:   failingCount,
	}
}

// computeSLAScore returns (subScore, breachRatePct). Both are zero
// when no SLA was configured or no findings were tracked, mirroring
// the original Compute() behavior.
func computeSLAScore(input Input) (subScore, breachRatePct float64) {
	subScore = 1.0
	if input.HasSLA && input.SLATotal > 0 {
		subScore = 1.0 - (float64(input.SLABreached) / float64(input.SLATotal))
		breachRatePct = float64(input.SLABreached) / float64(input.SLATotal) * 100
	}
	return subScore, breachRatePct
}

// computeChainScore turns the active-chain set into the chain
// sub-score plus the max/active weight totals for the Result detail.
func computeChainScore(input Input) chainResult {
	var maxW, activeW float64
	switch {
	case input.MaxChainWeight > 0:
		maxW = input.MaxChainWeight
	case input.ChainDefs > 0:
		// Fallback: assume all chains are critical when actual weights unavailable.
		maxW = float64(input.ChainDefs) * 10.0
	}
	for i := range input.ChainFindings {
		cw := chainWeight[input.ChainFindings[i].Severity]
		if cw == 0 {
			cw = 2.0
		}
		activeW += cw
	}
	subScore := 1.0
	if maxW > 0 {
		subScore = 1.0 - (activeW / maxW)
		if subScore < 0 {
			subScore = 0
		}
	}
	return chainResult{
		subScore:     subScore,
		maxWeight:    maxW,
		activeWeight: activeW,
	}
}

// computeCoverageScore reports CoveragePct in [0,1] form, or 1.0 when
// no coverage data was supplied.
func computeCoverageScore(input Input) float64 {
	if input.HasCoverage {
		return input.CoveragePct / 100.0
	}
	return 1.0
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
