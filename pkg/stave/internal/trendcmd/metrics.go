package trendcmd

import (
	"strings"
	"time"

	evidenceadapter "github.com/sufield/stave/internal/adapters/evidence"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// runMetrics captures posture metrics for a single assessment run.
type runMetrics struct {
	CapturedAt time.Time `json:"captured_at"`
	FilePath   string    `json:"-"`
	// TotalAssets is the denominator ViolationRate is computed against
	// (violations / TotalAssets). Carried so computeProjection targets the
	// same denominator instead of mixing findings with compliant-asset
	// counts. Internal-only ("-") to avoid widening the trend JSON shape.
	TotalAssets        int            `json:"-"`
	ViolationCount     int            `json:"violation_count"`
	PassCount          int            `json:"pass_count"`
	IncompleteCount    int            `json:"incomplete_count"`
	ViolationRate      float64        `json:"violation_rate"`
	BySeverity         map[string]int `json:"by_severity"`
	ByAttackStage      map[string]int `json:"by_attack_stage,omitempty"`
	ViolationsAdded    int            `json:"violations_added"`
	ViolationsResolved int            `json:"violations_resolved"`
}

// mttrEntry holds MTTR data for a single severity level.
type mttrEntry struct {
	AvgDays     float64 `json:"avg_days"`
	WindowCount int     `json:"window_count"`
}

// frameworkTrend captures a framework's satisfaction rate over time.
type frameworkTrend struct {
	Framework string    `json:"framework"`
	Scores    []float64 `json:"scores"`
	Direction string    `json:"direction"`
}

// Arrow returns the long arrow + label suffix the table renderer
// appends after the score series ("  ↑ improving" / "  ↓ regressing"
// / ""). Centralises the per-direction text so render_table stops
// switching on Direction at the call site.
func (ft frameworkTrend) Arrow() string {
	switch ft.Direction {
	case "improving":
		return "  ↑ improving"
	case "regressing":
		return "  ↓ regressing"
	default:
		return ""
	}
}

// Symbol returns the single-character trajectory glyph used by the
// table renderer ("^", "v", "-"). Mirrors the existing arrowFor
// helper but lives on the type so a future direction value lands
// in one place.
func (ft frameworkTrend) Symbol() string {
	switch ft.Direction {
	case "improving":
		return "^"
	case "regressing":
		return "v"
	default:
		return "-"
	}
}

// MetricValue returns the openmetrics integer encoding of the
// trend direction (1 / -1 / 0). Replaces the inline switch in
// render_openmetrics so all direction renderings share one source
// of truth.
func (ft frameworkTrend) MetricValue() int {
	switch ft.Direction {
	case "improving":
		return 1
	case "regressing":
		return -1
	default:
		return 0
	}
}

// slaTrendMetric captures SLA compliance for a single run.
type slaTrendMetric struct {
	CapturedAt        time.Time      `json:"captured_at"`
	TotalWithSLA      int            `json:"total_with_sla"`
	BreachedCount     int            `json:"breached_count"`
	CompliancePercent float64        `json:"compliance_rate_percent"`
	BreachedBySev     map[string]int `json:"breached_by_severity,omitempty"`
}

// trendReport is the complete trend analysis output.
type trendReport struct {
	GeneratedAt     time.Time            `json:"generated_at"`
	Period          period               `json:"period"`
	Summary         trendSummary         `json:"summary"`
	Runs            []runMetrics         `json:"runs"`
	MTTR            map[string]mttrEntry `json:"mttr,omitempty"`
	FrameworkTrends []frameworkTrend     `json:"framework_trends"`
	Velocity        velocityMetrics      `json:"velocity"`
	Projection      *projectionMetrics   `json:"projection,omitempty"`
	SLATrend        []slaTrendMetric     `json:"sla_trend,omitempty"`
	PostureScore    *float64             `json:"posture_score,omitempty"`
	PostureRubric   string               `json:"posture_rubric,omitempty"`
	TeamSummary     *teamTrendSummary    `json:"team_summary,omitempty"`
	TeamTrends      []teamTrend          `json:"team_trends,omitempty"`
	Rollup          *rollupResult        `json:"rollup,omitempty"`
}

// rollupResult holds aggregated metrics for a hierarchy group.
type rollupResult struct {
	GroupID      string  `json:"group_id"`
	GroupName    string  `json:"group_name"`
	PostureScore float64 `json:"posture_score"`
	MTTRHours    float64 `json:"mttr_hours"`
	SLACompPct   float64 `json:"sla_compliance_pct"`
	OpenFindings int     `json:"open_findings"`
	CriticalOpen int     `json:"critical_open"`
}

// period defines the time range of the trend analysis.
type period struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	RunCount int       `json:"run_count"`
}

// trendSummary provides high-level direction.
type trendSummary struct {
	FirstViolationRate  float64 `json:"first_violation_rate"`
	LatestViolationRate float64 `json:"latest_violation_rate"`
	NetChangePercent    float64 `json:"net_change_percent"`
	Direction           string  `json:"direction"`
}

// velocityMetrics captures the rate of change.
type velocityMetrics struct {
	WindowRuns   int     `json:"window_runs"`
	AvgNetChange float64 `json:"avg_net_change_per_run"`
	Direction    string  `json:"direction"`
}

// teamTrend holds per-team trend metrics.
type teamTrend struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Contact      string    `json:"contact,omitempty"`
	PostureScore float64   `json:"posture_score"`
	ScoreDelta   float64   `json:"posture_score_delta"`
	Trajectory   string    `json:"trajectory"`
	MTTRHours    float64   `json:"mttr_hours"`
	SLACompPct   float64   `json:"sla_compliance_pct"`
	OpenFindings int       `json:"open_findings"`
	CriticalOpen int       `json:"critical_open"`
	ScoreHistory []float64 `json:"score_history,omitempty"`
}

// IsImproving reports whether the team's posture is trending
// upward. Replaces direct (Trajectory == trajectoryImproving)
// probes at filter / aggregation / rendering sites. Pointer
// receiver matches ClassifyTrajectory below (recvcheck-clean).
func (t *teamTrend) IsImproving() bool {
	return t != nil && t.Trajectory == trajectoryImproving
}

// IsRegressing reports whether the team's posture is trending
// downward.
func (t *teamTrend) IsRegressing() bool {
	return t != nil && t.Trajectory == trajectoryRegressing
}

// IsStable reports whether the team's delta is within the stable
// band (the default classification when neither improving nor
// regressing fires).
func (t *teamTrend) IsStable() bool {
	return t != nil && t.Trajectory == trajectoryStable
}

// teamTrends is the slice alias the summary tally hangs off so
// the per-trajectory switch lives on the collection rather than
// the cmd/trend renderer.
type teamTrends []teamTrend

// TallyTrajectories walks the slice and returns the
// (improving, regressing, stable) counts. Replaces the inline
// IsImproving / IsRegressing / default switch in
// cmd/trend/team_trend.go's summary builder.
func (s teamTrends) TallyTrajectories() (improving, regressing, stable int) {
	for i := range s {
		switch {
		case s[i].IsImproving():
			improving++
		case s[i].IsRegressing():
			regressing++
		default:
			stable++
		}
	}
	return improving, regressing, stable
}

// ClassifyTrajectory sets Trajectory based on delta vs threshold:
//   - delta ≥  threshold → trajectoryImproving
//   - delta ≤ -threshold → trajectoryRegressing
//   - otherwise         → trajectoryStable
//
// Centralises the rule that computeTeamTrends used to reproduce
// inline. Pointer receiver because this mutates the field.
func (t *teamTrend) ClassifyTrajectory(delta, threshold float64) {
	if t == nil {
		return
	}
	switch {
	case delta >= threshold:
		t.Trajectory = trajectoryImproving
	case delta <= -threshold:
		t.Trajectory = trajectoryRegressing
	default:
		t.Trajectory = trajectoryStable
	}
}

// Symbol returns the single-character trajectory glyph for the
// table renderer ("^", "v", "-"). Mirrors frameworkTrend.Symbol so
// both shapes ask the same method name for the same answer.
func (t *teamTrend) Symbol() string {
	if t == nil {
		return "-"
	}
	switch t.Trajectory {
	case trajectoryImproving:
		return "^"
	case trajectoryRegressing:
		return "v"
	default:
		return "-"
	}
}

// MetricValue returns the openmetrics integer encoding of the
// trajectory (1 / -1 / 0). Replaces the inline switch in
// render_openmetrics.
func (t *teamTrend) MetricValue() int {
	if t == nil {
		return 0
	}
	switch t.Trajectory {
	case trajectoryImproving:
		return 1
	case trajectoryRegressing:
		return -1
	default:
		return 0
	}
}

// teamTrendSummary holds aggregate team statistics.
type teamTrendSummary struct {
	TeamsTracked    int `json:"teams_tracked"`
	TeamsImproving  int `json:"teams_improving"`
	TeamsStable     int `json:"teams_stable"`
	TeamsRegressing int `json:"teams_regressing"`
}

// projectionMetrics provides a linear extrapolation.
type projectionMetrics struct {
	TargetRate    float64 `json:"target_rate"`
	EstimatedRuns int     `json:"estimated_runs"`
	Basis         string  `json:"basis"`
	Caveat        string  `json:"caveat"`
}

// computeRunMetrics extracts metrics from a single assessment.
func computeRunMetrics(a *report.Assessment, prev *runMetrics) runMetrics {
	violations := len(a.Findings)
	total := a.Summary.TotalAssets
	passCount := total - a.Summary.ExposedResources

	rate := 0.0
	if total > 0 {
		rate = float64(violations) / float64(total)
	}

	counts := a.CountBySeverity()
	bySeverity := counts.AsMap()
	if bySeverity == nil {
		bySeverity = map[string]int{}
	}
	// Preserve the unknown-severity bucket: CountBySeverity drops
	// findings outside (critical/high/medium/low), but trend metrics
	// historically surfaced the residue under "unknown" so report
	// readers see when the catalog produces unmapped tiers.
	if unknown := len(a.Findings) - counts.Total(); unknown > 0 {
		bySeverity["unknown"] = unknown
	}

	byStage := make(map[string]int)
	for stage, count := range a.AttackStageSummary {
		n := 0
		for _, c := range count {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 {
			byStage[string(stage)] = n
		}
	}

	m := runMetrics{
		CapturedAt:     a.Run.Now,
		TotalAssets:    total,
		ViolationCount: violations,
		PassCount:      passCount,
		ViolationRate:  rate,
		BySeverity:     bySeverity,
		ByAttackStage:  byStage,
	}

	// Compute delta from previous run.
	if prev != nil {
		// Count from the difference perspective: what's new vs what's gone.
		m.ViolationsAdded = max(0, violations-prev.ViolationCount)
		m.ViolationsResolved = max(0, prev.ViolationCount-violations)
	}

	return m
}

// computeVelocity computes rolling average net change.
func computeVelocity(runs []runMetrics, windowSize int) velocityMetrics {
	if len(runs) < 2 {
		return velocityMetrics{Direction: "insufficient_data"}
	}

	start := 0
	if windowSize > 0 && len(runs) > windowSize {
		start = len(runs) - windowSize
	}
	window := runs[start:]
	// A window of fewer than two runs has no delta to average; dividing
	// by float64(len(window)-1) would be 0.0/0.0 = NaN, and because every
	// NaN comparison is false the direction would silently fall through to
	// "steady". Classify it honestly as insufficient_data instead.
	if len(window) < 2 {
		return velocityMetrics{Direction: "insufficient_data"}
	}

	totalDelta := 0.0
	for i := 1; i < len(window); i++ {
		totalDelta += float64(window[i].ViolationCount - window[i-1].ViolationCount)
	}
	avg := totalDelta / float64(len(window)-1)

	dir := "steady"
	if avg < -0.5 {
		dir = "improving"
	} else if avg > 0.5 {
		dir = "regressing"
	}

	return velocityMetrics{
		WindowRuns:   len(window),
		AvgNetChange: avg,
		Direction:    dir,
	}
}

// computeProjection provides a linear extrapolation if improving.
func computeProjection(runs []runMetrics, velocity velocityMetrics) *projectionMetrics {
	if velocity.Direction != "improving" || len(runs) == 0 {
		return nil
	}

	latestRate := runs[len(runs)-1].ViolationRate
	targetRate := 0.05

	if latestRate <= targetRate {
		return nil // already at target
	}

	// Estimate: how many runs at current velocity to reach target.
	latestCount := float64(runs[len(runs)-1].ViolationCount)
	if velocity.AvgNetChange >= 0 {
		return nil
	}

	// Target violation COUNT at which the rate hits targetRate. The rate is
	// violations/TotalAssets (see computeRunMetrics), so the denominator
	// here must be TotalAssets — not ViolationCount+PassCount, which mixes
	// findings (a count that can exceed assets when one asset trips several
	// controls) with compliant-asset counts and inflates the target.
	targetCount := targetRate * float64(runs[len(runs)-1].TotalAssets)
	runsNeeded := int((latestCount - targetCount) / (-velocity.AvgNetChange))
	if runsNeeded <= 0 {
		runsNeeded = 1
	}

	return &projectionMetrics{
		TargetRate:    targetRate,
		EstimatedRuns: runsNeeded,
		Basis:         "linear_extrapolation",
		Caveat:        "Linear projection only. Security posture is not linear.",
	}
}

// computeFrameworkTrends computes per-framework satisfaction rates across runs.
func computeFrameworkTrends(assessments []*report.Assessment, complianceFlag string) []frameworkTrend {
	if complianceFlag == "" {
		return []frameworkTrend{}
	}

	frameworks := strings.Split(complianceFlag, ",")
	for i := range frameworks {
		frameworks[i] = strings.TrimSpace(frameworks[i])
	}

	// Load framework profiles for requirement counts.
	profileReqs := make(map[string]int) // framework → total requirements
	for _, fw := range frameworks {
		p, err := evidenceadapter.LoadProfile(fw)
		if err != nil {
			continue
		}
		profileReqs[fw] = len(p.Requirements)
	}

	var trends []frameworkTrend
	for _, fw := range frameworks {
		totalReqs := profileReqs[fw]
		if totalReqs == 0 {
			continue
		}

		var scores []float64
		for _, a := range assessments {
			violated := remediation.FindingSet(a.Findings).ViolatedRequirements(policy.ComplianceFramework(fw))
			satisfied := totalReqs - len(violated)
			score := float64(satisfied) / float64(totalReqs)
			scores = append(scores, score)
		}

		dir := "stable"
		if len(scores) >= 2 {
			last := scores[len(scores)-1]
			prev := scores[len(scores)-2]
			if last > prev {
				dir = "improving"
			} else if last < prev {
				dir = "regressing"
			}
		}

		trends = append(trends, frameworkTrend{
			Framework: fw,
			Scores:    scores,
			Direction: dir,
		})
	}
	return trends
}

// computeSLATrend extracts SLA compliance rate per assessment run.
// Runs where no findings have SLA data are skipped.
func computeSLATrend(assessments []*report.Assessment) []slaTrendMetric {
	var metrics []slaTrendMetric
	for _, a := range assessments {
		stats := remediation.FindingSet(a.Findings).SLABreachSummary()
		if stats.TotalWithSLA == 0 {
			continue
		}
		withinSLA := stats.TotalWithSLA - stats.BreachedCount
		pct := float64(withinSLA) / float64(stats.TotalWithSLA) * 100
		metrics = append(metrics, slaTrendMetric{
			CapturedAt:        a.Run.Now,
			TotalWithSLA:      stats.TotalWithSLA,
			BreachedCount:     stats.BreachedCount,
			CompliancePercent: pct,
			BreachedBySev:     stats.BreachedBySeverity,
		})
	}
	return metrics
}
