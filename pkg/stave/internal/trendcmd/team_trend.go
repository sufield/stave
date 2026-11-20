package trendcmd

import (
	"cmp"
	"fmt"
	"io"
	"slices"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

const (
	trajectoryImproving  = "IMPROVING"
	trajectoryStable     = "STABLE"
	trajectoryRegressing = "REGRESSING"
	// trajectoryThreshold is the minimum score delta to classify
	// as improving or regressing (prevents noise).
	trajectoryThreshold = 5.0
)

// computeTeamTrends attributes findings to teams and computes per-team metrics.
func computeTeamTrends(
	assessments []*report.Assessment,
	manifest *teams.Manifest,
	teamFilter string,
	regressionOnly bool,
) ([]teamTrend, *teamTrendSummary) {
	if manifest == nil || len(assessments) == 0 {
		return nil, nil
	}

	// Compute per-team metrics for the latest assessment.
	latest := assessments[len(assessments)-1]

	// Group findings by team.
	teamFindings := make(map[teams.TeamID][]remediation.Finding)
	for i := range latest.Findings {
		f := &latest.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), f.ControlID)
		teamFindings[owner.TeamID] = append(teamFindings[owner.TeamID], *f)
	}

	// Build team lookup.
	teamLookup := make(map[teams.TeamID]*teams.Team)
	for i := range manifest.Teams {
		teamLookup[manifest.Teams[i].ID] = &manifest.Teams[i]
	}

	var earlierScores map[teams.TeamID]float64
	if len(assessments) > 1 {
		earlierScores = baselineScores(assessments[0], manifest)
	}

	// Compute team trends.
	var trends []teamTrend
	for i := range manifest.Teams {
		t := &manifest.Teams[i]
		if teamFilter != "" && string(t.ID) != teamFilter {
			continue
		}
		if tt, ok := computeOneTeamTrend(t, teamFindings[t.ID], earlierScores, regressionOnly); ok {
			trends = append(trends, tt)
		}
	}

	// Also include "unassigned" if there are unassigned findings.
	if teamFilter == "" {
		if uf := teamFindings["unassigned"]; len(uf) > 0 {
			trends = append(trends, teamTrend{
				ID:           "unassigned",
				Name:         "Unassigned",
				PostureScore: 0,
				Trajectory:   trajectoryStable,
				OpenFindings: len(uf),
			})
		}
	}

	// Sort by score descending.
	slices.SortFunc(trends, func(a, b teamTrend) int {
		return cmp.Compare(b.PostureScore, a.PostureScore)
	})

	// Summary.
	improving, regressing, stable := teamTrends(trends).TallyTrajectories()
	summary := &teamTrendSummary{
		TeamsTracked:    len(trends),
		TeamsImproving:  improving,
		TeamsRegressing: regressing,
		TeamsStable:     stable,
	}

	return trends, summary
}

func computeOneTeamTrend(t *teams.Team, findings []remediation.Finding, earlierScores map[teams.TeamID]float64, regressionOnly bool) (teamTrend, bool) {
	totalResources := max(len(findings), 1)
	score := (1.0 - float64(len(findings))/float64(totalResources)) * 100
	if len(findings) == 0 {
		score = 100.0
	}

	var delta float64
	if es, ok := earlierScores[t.ID]; ok {
		delta = score - es
	} else if len(findings) == 0 && earlierScores != nil {
		delta = 0
	}
	var stage teamTrend
	stage.ClassifyTrajectory(delta, trajectoryThreshold)

	if regressionOnly && !stage.IsRegressing() {
		return teamTrend{}, false
	}

	stats := remediation.FindingSet(findings).SLASummary()
	var totalDwell float64
	for j := range findings {
		totalDwell += findings[j].DwellHours()
	}

	mttr := 0.0
	if len(findings) > 0 {
		mttr = totalDwell / float64(len(findings))
	}

	slaPct := 100.0
	if stats.SLATotal > 0 {
		slaPct = float64(stats.SLAWithinTarget) / float64(stats.SLATotal) * 100
	}

	return teamTrend{
		ID:           t.ID,
		Name:         t.DisplayName,
		Contact:      t.Contact,
		PostureScore: score,
		ScoreDelta:   delta,
		Trajectory:   stage.Trajectory,
		MTTRHours:    mttr,
		SLACompPct:   slaPct,
		OpenFindings: len(findings),
		CriticalOpen: stats.Critical,
	}, true
}

func baselineScores(earliest *report.Assessment, manifest *teams.Manifest) map[teams.TeamID]float64 {
	byTeam := make(map[teams.TeamID]int)
	for i := range earliest.Findings {
		f := &earliest.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), f.ControlID)
		byTeam[owner.TeamID]++
	}
	scores := make(map[teams.TeamID]float64, len(byTeam))
	for tid, count := range byTeam {
		total := max(count, 1)
		scores[tid] = (1.0 - float64(count)/float64(total)) * 100
	}
	return scores
}

// computeRollup aggregates team trends for a hierarchy group.
func computeRollup(trends []teamTrend, group *teams.HierarchyGroup) *rollupResult {
	if group == nil {
		return nil
	}
	memberSet := make(map[teams.TeamID]struct{}, len(group.Teams))
	for _, tid := range group.Teams {
		memberSet[tid] = struct{}{}
	}

	var totalScore, totalMTTR float64
	var totalSLAWithin, totalSLAAll int
	var openFindings, criticalOpen, count int
	for i := range trends {
		t := &trends[i]
		if _, ok := memberSet[t.ID]; !ok {
			continue
		}
		count++
		totalScore += t.PostureScore
		totalMTTR += t.MTTRHours
		openFindings += t.OpenFindings
		criticalOpen += t.CriticalOpen
		// Approximate SLA: convert percentage back to counts.
		if t.OpenFindings > 0 {
			within := int(t.SLACompPct / 100 * float64(t.OpenFindings))
			totalSLAWithin += within
			totalSLAAll += t.OpenFindings
		}
	}
	if count == 0 {
		return nil
	}

	slaPct := 100.0
	if totalSLAAll > 0 {
		slaPct = float64(totalSLAWithin) / float64(totalSLAAll) * 100
	}

	return &rollupResult{
		GroupID:      string(group.ID),
		GroupName:    group.Name,
		PostureScore: totalScore / float64(count),
		MTTRHours:    totalMTTR / float64(count),
		SLACompPct:   slaPct,
		OpenFindings: openFindings,
		CriticalOpen: criticalOpen,
	}
}

// renderExecutiveSummary writes a plain-text paragraph for board reporting.
func renderExecutiveSummary(w io.Writer, r *trendReport) error { //nolint:unparam // error return for format-dispatch consistency
	score := 0.0
	if r.PostureScore != nil {
		score = *r.PostureScore
	}
	delta := r.Summary.NetChangePercent
	date := r.Period.End.Format("2006-01-02")

	direction := "remained stable"
	if delta > 0 {
		direction = fmt.Sprintf("improved %.1f points", delta)
	} else if delta < 0 {
		direction = fmt.Sprintf("declined %.1f points", -delta)
	}

	fmt.Fprintf(w, "EXECUTIVE SECURITY SUMMARY — %s\n\n", date)
	fmt.Fprintf(w, "Account posture %s to %.1f.", direction, score)

	if r.HasTeamPostureTrends() {
		ts := r.TeamSummary
		fmt.Fprintf(w, " %d of %d teams are improving, %d are stable, %d require attention.\n",
			ts.TeamsImproving, ts.TeamsTracked, ts.TeamsStable, ts.TeamsRegressing)

		writeRegressingAlerts(w, r.TeamTrends)
		writeTopPerformer(w, r.TeamTrends)
	} else {
		fmt.Fprintln(w)
	}

	return nil
}

func writeRegressingAlerts(w io.Writer, trends []teamTrend) {
	for i := range trends {
		t := &trends[i]
		if t.Trajectory != trajectoryRegressing {
			continue
		}
		name := t.Name
		if name == "" {
			name = string(t.ID)
		}
		fmt.Fprintf(w, "\nATTENTION REQUIRED: %s (score %.1f, %+.1f). %d critical findings open.",
			name, t.PostureScore, t.ScoreDelta, t.CriticalOpen)
		if t.Contact != "" {
			fmt.Fprintf(w, " Contact: %s.", t.Contact)
		}
		fmt.Fprintln(w)
	}
}

func writeTopPerformer(w io.Writer, trends []teamTrend) {
	var best *teamTrend
	for i := range trends {
		t := &trends[i]
		if t.Trajectory == trajectoryImproving {
			if best == nil || t.ScoreDelta > best.ScoreDelta {
				best = t
			}
		}
	}
	if best == nil {
		return
	}
	name := best.Name
	if name == "" {
		name = string(best.ID)
	}
	fmt.Fprintf(w, "\nTop performer: %s (score %.1f, %+.1f, MTTR %.1fh, %.0f%% SLA compliance).\n",
		name, best.PostureScore, best.ScoreDelta, best.MTTRHours, best.SLACompPct)
}
