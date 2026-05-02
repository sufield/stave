// Package monitor aggregates posture data from assessment history
// into a single view for the stave monitor command.
package monitor

import (
	"cmp"
	"slices"

	appscore "github.com/sufield/stave/internal/app/score"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// State holds the aggregated monitor data.
type State struct {
	GeneratedAt  string             `json:"generated_at"`
	Score        float64            `json:"posture_score"`
	ScoreDelta   float64            `json:"posture_score_delta"`
	ScoreTrend   string             `json:"posture_score_trend"`
	ScoreHist    []float64          `json:"score_history,omitempty"`
	Findings     FindingSummary     `json:"findings"`
	SLABurn      map[string]float64 `json:"sla_burn_rates,omitempty"`
	TopFindings  []TopFinding       `json:"top_findings"`
	ATTCKTactics []TacticRow        `json:"attack_coverage"`
	Catalog      CatalogCounts      `json:"catalog"`
}

// FindingSummary holds severity counts.
type FindingSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// TopFinding is a finding for display.
type TopFinding struct {
	ControlID   string  `json:"control_id"`
	Severity    string  `json:"severity"`
	DwellHours  float64 `json:"dwell_hours"`
	BlastRadius float64 `json:"blast_radius"`
	SLABurnRate float64 `json:"sla_burn_rate"`
	SLABreached bool    `json:"sla_breached"`
}

// IsAnyBreach reports whether the underlying finding has breached
// its SLA. Mirrors evaluation.Finding.IsAnyBreach so monitor render
// asks the DTO for the answer instead of reading the field directly.
func (t *TopFinding) IsAnyBreach() bool {
	return t != nil && t.SLABreached
}

// TacticRow is one ATT&CK tactic for display.
type TacticRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Controls int    `json:"controls"`
	Status   string `json:"status"`
}

// CatalogCounts holds total controls and chains.
type CatalogCounts struct {
	Controls int `json:"controls"`
	Chains   int `json:"chains"`
}

// BuildInput holds pre-loaded data for building monitor state.
type BuildInput struct {
	GeneratedAt    string
	Assessments    []*report.Assessment
	ChainDefs      int
	MaxChainWeight float64
	SLADeadlines   map[string]float64 // severity → deadline hours, nil if no SLA
}

// Build aggregates monitor state from pre-loaded assessments.
func Build(input BuildInput) *State {
	assessments := input.Assessments
	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})

	latest := assessments[len(assessments)-1]
	scoreResult := computeScore(latest, input.ChainDefs, input.MaxChainWeight)

	var scoreDelta float64
	if len(assessments) > 1 {
		earlier := computeScore(assessments[0], input.ChainDefs, input.MaxChainWeight)
		scoreDelta = scoreResult.Score - earlier.Score
	}

	trend := "STABLE"
	if scoreDelta >= 5 {
		trend = "IMPROVING"
	} else if scoreDelta <= -5 {
		trend = "REGRESSING"
	}

	// scoreSparklinePoints controls how many data points appear in the
	// trend sparkline. 8 points gives weekly granularity in a 2-month window.
	const scoreSparklinePoints = 8
	var scoreHist []float64
	step := max(1, len(assessments)/scoreSparklinePoints)
	for i := 0; i < len(assessments); i += step {
		s := computeScore(assessments[i], input.ChainDefs, input.MaxChainWeight)
		scoreHist = append(scoreHist, s.Score)
	}
	if len(scoreHist) > 0 && scoreHist[len(scoreHist)-1] != scoreResult.Score {
		scoreHist = append(scoreHist, scoreResult.Score)
	}

	fs := countFindings(latest.Findings)

	var slaBurn map[string]float64
	if input.SLADeadlines != nil {
		slaBurn = computeSLABurnFromDeadlines(latest.Findings, input.SLADeadlines)
	}

	return &State{
		GeneratedAt: input.GeneratedAt,
		Score:       scoreResult.Score,
		ScoreDelta:  scoreDelta,
		ScoreTrend:  trend,
		ScoreHist:   scoreHist,
		Findings:    fs,
		SLABurn:     slaBurn,
		TopFindings: rankFindings(latest.Findings, 5),
		Catalog:     CatalogCounts{Chains: input.ChainDefs},
	}
}

func computeScore(a *report.Assessment, chainDefs int, maxChainWeight float64) appscore.Result {
	slaTotal, slaBreached := 0, 0
	for i := range a.Findings {
		if a.Findings[i].HasSLA() {
			slaTotal++
			if a.Findings[i].IsOverdue() {
				slaBreached++
			}
		}
	}
	return appscore.Compute(appscore.Input{
		Findings:       a.Findings,
		ChainFindings:  a.ChainFindings,
		ChainDefs:      chainDefs,
		MaxChainWeight: maxChainWeight,
		SLABreached:    slaBreached,
		SLATotal:       slaTotal,
		HasSLA:         slaTotal > 0,
		Weights:        appscore.DefaultWeights(),
		GeneratedAt:    a.Run.Now,
	})
}

func countFindings(findings []remediation.Finding) FindingSummary {
	var fs FindingSummary
	fs.Total = len(findings)
	for i := range findings {
		switch findings[i].ControlSeverity.BucketName() {
		case "critical":
			fs.Critical++
		case "high":
			fs.High++
		case "medium":
			fs.Medium++
		case "low":
			fs.Low++
		}
	}
	return fs
}

func computeSLABurnFromDeadlines(findings []remediation.Finding, deadlines map[string]float64) map[string]float64 {
	burn := map[string]float64{}
	counts := map[string]int{}
	for i := range findings {
		f := &findings[i]
		sev := f.ControlSeverity.String()
		deadline := deadlines[sev]
		if deadline <= 0 {
			continue
		}
		burn[sev] += f.Evidence.UnsafeDurationHours / deadline
		counts[sev]++
	}
	for sev, total := range burn {
		if counts[sev] > 0 {
			burn[sev] = total / float64(counts[sev])
		}
	}
	return burn
}

func rankFindings(findings []remediation.Finding, n int) []TopFinding {
	type ranked struct {
		idx   int
		score float64
	}
	var items []ranked
	for i := range findings {
		f := &findings[i]
		w, ok := policy.SeverityWeight(f.ControlSeverity)
		if !ok {
			// Unrecognized severity (e.g. SeverityNone, SeverityInfo)
			// drops to the lowest non-zero rank rather than 0,
			// which would zero out burnRate's contribution and let
			// SLA-overdue findings rank below scored ones.
			w = 1.0
		}
		burnRate := 0.0
		if dl, ok := f.SLADeadlineValue(); ok && dl > 0 {
			burnRate = f.Evidence.UnsafeDurationHours / dl
		}
		items = append(items, ranked{idx: i, score: w*100 + burnRate*50})
	}
	slices.SortFunc(items, func(a, b ranked) int { return cmp.Compare(b.score, a.score) })
	if len(items) > n {
		items = items[:n]
	}
	var result []TopFinding
	for _, item := range items {
		f := &findings[item.idx]
		tf := TopFinding{
			ControlID:   string(f.ControlID),
			Severity:    f.SeverityLabel(),
			DwellHours:  f.Evidence.UnsafeDurationHours,
			SLABreached: f.IsAnyBreach(),
		}
		if dl, ok := f.SLADeadlineValue(); ok && dl > 0 {
			tf.SLABurnRate = f.Evidence.UnsafeDurationHours / dl
		}
		result = append(result, tf)
	}
	return result
}
