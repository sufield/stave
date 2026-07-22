// Package score computes the 0-100 security posture score.
package score

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/findings"
)

// weightSumEpsilon is the floating-point tolerance for "weights sum
// to 1.0". Using bare equality on float64 sums of four 0.x values
// fails for distributions like {0.45, 0.25, 0.2, 0.1} because the
// last decimal cannot be represented exactly in IEEE 754. 1e-9 is
// well above the four-addend round-off floor (~1e-16) and well below
// any meaningful difference an operator would intend.
const weightSumEpsilon = 1e-9

// Weights controls the relative importance of each score dimension.
// All four values must be non-negative and sum to 1.0 within
// weightSumEpsilon — see NewWeights / Validate / UnmarshalJSON.
//
// Why enforce 1.0 strictly: the score formula is
// sev*Severity + sla*SLA + chain*Chain + cov*Coverage, where every
// sub-score is in [0, 1]. A sum > 1.0 produces a "120% secure"
// reading; a sum < 1.0 produces a permanently-capped score that
// looks like the system can't reach a clean state. Either makes the
// rubric bands meaningless, so the sum-to-1 invariant lives on the
// type rather than as a per-call assertion.
type Weights struct {
	Severity float64 `json:"severity"`
	SLA      float64 `json:"sla"`
	Chain    float64 `json:"chain"`
	Coverage float64 `json:"coverage"`
}

// NewWeights returns a Weights value after enforcing the sum-to-1
// invariant. Caller-provided weights must be non-negative and sum to
// 1.0 within weightSumEpsilon — see the package doc on Weights for
// why this matters.
func NewWeights(severity, sla, chain, coverage float64) (Weights, error) {
	w := Weights{Severity: severity, SLA: sla, Chain: chain, Coverage: coverage}
	if err := w.Validate(); err != nil {
		return Weights{}, err
	}
	return w, nil
}

// Validate enforces the sum-to-1 / non-negative invariants documented
// on Weights.
func (w Weights) Validate() error {
	if w.Severity < 0 || w.SLA < 0 || w.Chain < 0 || w.Coverage < 0 {
		return fmt.Errorf("weights must be non-negative: got severity=%v sla=%v chain=%v coverage=%v",
			w.Severity, w.SLA, w.Chain, w.Coverage)
	}
	sum := w.Severity + w.SLA + w.Chain + w.Coverage
	if math.Abs(sum-1.0) > weightSumEpsilon {
		return fmt.Errorf("weights must sum to 1.0 (got %v: severity=%v sla=%v chain=%v coverage=%v)",
			sum, w.Severity, w.SLA, w.Chain, w.Coverage)
	}
	return nil
}

// UnmarshalJSON decodes the weight set and runs Validate so an
// external config cannot inject a sum > 1.0 ("120% secure" scores)
// or a sum < 1.0 (permanently-capped scores).
func (w *Weights) UnmarshalJSON(data []byte) error {
	type alias Weights
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	candidate := Weights(a)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*w = candidate
	return nil
}

// DefaultWeights returns the standard weight distribution. The values
// are chosen so the sum is exactly 1.0 in IEEE 754 (severity=0.45 +
// sla=0.25 + chain=0.20 + coverage=0.10) and the function uses
// NewWeights so the invariants stay enforced even for the canonical
// distribution. Panics on construction failure — DefaultWeights is
// known-good at compile time and a runtime failure would mean a
// regression in the constants above.
func DefaultWeights() Weights {
	w, err := NewWeights(0.45, 0.25, 0.20, 0.10)
	if err != nil {
		panic(fmt.Sprintf("score: DefaultWeights invariant violated: %v", err))
	}
	return w
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

// ScoreMover names a sub-score component that is currently
// dragging the posture score below its maximum, with the count of
// findings driving the impact and the points lost. Centralised on
// Result so the CLI display layer doesn't reach 3 levels deep into
// component / detail fields per render.
type ScoreMover struct {
	// Component identifies which sub-score this mover comes from
	// — "severity", "sla", "chain", or "coverage".
	Component string
	// Count is the impactful unit (failing findings, breaches,
	// active chains). For coverage it is the percentage rounded to
	// the nearest integer.
	Count int
	// PointsLost is the contribution gap (max - actual) in score
	// points.
	PointsLost float64
}

// Label returns the human-readable mover-row label the score CLI
// renderer prints. Centralises the per-component template so
// cmd/score's formatMover stops switching on m.Component at the
// call site. Unknown components fall through to a generic shape.
//
// Note: the points-lost suffix is the same across rows; this
// method returns only the leading "<count> <message>" portion so
// the caller can append the (-N.N pts) tail in its preferred
// width-aligned form.
func (m ScoreMover) Label() string {
	switch m.Component {
	case "severity":
		return fmt.Sprintf("%d findings currently failing", m.Count)
	case "sla":
		return fmt.Sprintf("%d SLA breach(es)", m.Count)
	case "chain":
		return fmt.Sprintf("%d active compound chain(s)", m.Count)
	case "coverage":
		return fmt.Sprintf("Framework coverage %d%%", m.Count)
	default:
		return m.Component + " impact"
	}
}

// Movers returns the sub-score components that have lost points
// for this Result, in the canonical (severity, SLA, chain,
// coverage) order. Each entry carries the structured numbers the
// renderer needs so display layers can format them without
// reaching into Severity.Detail / SLA.Detail / etc. directly.
func (r Result) Movers() []ScoreMover {
	movers := make([]ScoreMover, 0, 4)
	if r.Severity.Detail.FailingFindings > 0 {
		movers = append(movers, ScoreMover{
			Component:  "severity",
			Count:      r.Severity.Detail.FailingFindings,
			PointsLost: r.Severity.MaxContribution - r.Severity.Contribution,
		})
	}
	if r.SLA.Detail.FindingsBreached > 0 {
		movers = append(movers, ScoreMover{
			Component:  "sla",
			Count:      r.SLA.Detail.FindingsBreached,
			PointsLost: r.SLA.MaxContribution - r.SLA.Contribution,
		})
	}
	if r.Chain.Detail.ActiveChains > 0 {
		movers = append(movers, ScoreMover{
			Component:  "chain",
			Count:      r.Chain.Detail.ActiveChains,
			PointsLost: r.Chain.MaxContribution - r.Chain.Contribution,
		})
	}
	if r.Coverage.SubScore < 1.0 {
		movers = append(movers, ScoreMover{
			Component:  "coverage",
			Count:      int(r.Coverage.Detail.CoveragePct),
			PointsLost: r.Coverage.MaxContribution - r.Coverage.Contribution,
		})
	}
	return movers
}

// TrendDirection classifies the score's trajectory across the trend
// points using a ±1-point net-change threshold:
//   - "IMPROVING": last - first > 1
//   - "DECLINING": last - first < -1
//   - "STABLE":    otherwise (or fewer than 2 points)
//
// Centralised on Result so the cmd/score renderer stops open-coding
// the IMPROVING/DECLINING/STABLE branch against the trend slice.
// Returns "STABLE" with a zero net-change when no trend is recorded
// so callers can render unconditionally.
func (r Result) TrendDirection() (direction string, netChange float64) {
	if len(r.Trend) < 2 {
		return "STABLE", 0
	}
	netChange = r.Trend[len(r.Trend)-1].Score - r.Trend[0].Score
	switch {
	case netChange > 1:
		return "IMPROVING", netChange
	case netChange < -1:
		return "DECLINING", netChange
	default:
		return "STABLE", netChange
	}
}

// RubricBandNumeric maps the textual RubricBand to its numeric
// gauge representation used by the OpenMetrics exporter:
// strong=4, adequate=3, needs_attention=2, at_risk=1, critical=0.
// Centralised so consumers stop switching on the raw string.
func (r Result) RubricBandNumeric() int {
	switch r.RubricBand {
	case "strong":
		return 4
	case "adequate":
		return 3
	case "needs_attention":
		return 2
	case "at_risk":
		return 1
	default:
		return 0
	}
}

// Input holds data for score computation.
type Input struct {
	Findings         []remediation.Finding
	ChainFindings    []findings.CompoundFinding
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
	// Enforce the sum-to-1 invariant on parsed weights so a CLI-
	// supplied weight string that happens to sum to 0.99 does not
	// silently distort downstream score arithmetic. Validate
	// returns a UserError-friendly message.
	if err := w.Validate(); err != nil {
		return Weights{}, err
	}
	return w, nil
}

var severityWeight = map[policy.Severity]float64{
	policy.SeverityCritical: 10.0,
	policy.SeverityHigh:     4.0,
	policy.SeverityMedium:   2.0,
	policy.SeverityLow:      1.0,
	// Info findings carry zero exposure weight — they exist to
	// surface observations, not score them. Without an explicit
	// entry the map's zero-value lookup matched anyway, but
	// SeverityWeightFor's "0 → 1.0" fallback would have promoted
	// Info to Low's weight, which is exactly the misclassification
	// this entry prevents.
	policy.SeverityInfo: 0.0,
}

// SeverityWeightFor returns the score weight for a given severity level.
func SeverityWeightFor(sev policy.Severity) float64 {
	if w, ok := severityWeight[sev]; ok {
		return w
	}
	return 1.0
}

// chainWeight maps a chain's compound severity to its score weight.
// Mirrors severityWeight's full ladder so a chain authored at Low or
// Info severity scores against the same scale as a chain authored at
// Medium/High/Critical. The earlier shape omitted Low/Info, which
// silently routed those chains through the bare-map zero-value
// fallback and inflated their downstream weight to 2.0 (the
// fallback default).
var chainWeight = map[policy.Severity]float64{
	policy.SeverityCritical: 10.0,
	policy.SeverityHigh:     4.0,
	policy.SeverityMedium:   2.0,
	policy.SeverityLow:      1.0,
	policy.SeverityInfo:     0.0,
}

// ChainMaxWeight computes the severity-weighted maximum chain weight
// from actual chain definitions. Each chain contributes its
// CompoundSeverity weight (critical=10, high=4, medium=2, low=1,
// info=0). Unrecognised severities fall back to medium so a typo in
// a chain definition does not silently zero out its contribution.
func ChainMaxWeight(chains []policy.ChainDefinition) float64 {
	var total float64
	for i := range chains {
		cw, ok := chainWeight[chains[i].CompoundSeverity]
		if !ok {
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
		// NormalizedWeight is the canonical four-tier ladder; the type
		// owns the "every finding contributes ≥ 1.0" floor so this
		// loop can sum directly without a local correction.
		actualExposure += input.Findings[i].ControlSeverity.NormalizedWeight()
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
		maxSev := policy.SeverityCritical.NormalizedWeight()
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
		reportedMax = float64(failingCount) * policy.SeverityCritical.NormalizedWeight()
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
	// Clamp to [0, 1]. Adversarial input (SLABreached > SLATotal from
	// upstream miscount, fixture truncation) would otherwise produce
	// negative sub-scores that propagate into nonsense rubric bands;
	// matches the pin computeSeverityScore already applies.
	subScore = math.Max(0, math.Min(1.0, subScore))
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
		cw, ok := chainWeight[input.ChainFindings[i].Severity]
		if !ok {
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
		return math.Max(0, math.Min(1.0, input.CoveragePct/100.0))
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
