package trend

import (
	"sort"
	"strings"

	"fmt"
	"io"

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
) ([]TeamTrend, *TeamTrendSummary) {
	if manifest == nil || len(assessments) == 0 {
		return nil, nil
	}

	// Compute per-team metrics for the latest assessment.
	latest := assessments[len(assessments)-1]

	// Group findings by team.
	teamFindings := make(map[string][]remediation.Finding)
	for i := range latest.Findings {
		f := &latest.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		teamFindings[owner.TeamID] = append(teamFindings[owner.TeamID], *f)
	}

	// Build team lookup.
	teamLookup := make(map[string]*teams.Team)
	for i := range manifest.Teams {
		teamLookup[manifest.Teams[i].ID] = &manifest.Teams[i]
	}

	// If we have history, compute earlier scores for trajectory.
	var earlierScores map[string]float64
	if len(assessments) > 1 {
		earliest := assessments[0]
		earlierScores = make(map[string]float64)
		earlierByTeam := make(map[string]int)
		earlierTotalByTeam := make(map[string]int)
		for i := range earliest.Findings {
			f := &earliest.Findings[i]
			owner := manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
			earlierByTeam[owner.TeamID]++
		}
		// Estimate per-team score from violation count change.
		for tid := range earlierByTeam {
			total := earlierTotalByTeam[tid]
			if total == 0 {
				total = max(earlierByTeam[tid], 1)
			}
			rate := float64(earlierByTeam[tid]) / float64(total)
			earlierScores[tid] = (1.0 - rate) * 100
		}
	}

	// Compute team trends.
	var trends []TeamTrend
	for i := range manifest.Teams {
		t := &manifest.Teams[i]
		findings := teamFindings[t.ID]

		if teamFilter != "" && t.ID != teamFilter {
			continue
		}

		// Posture score: simple (1 - violation_rate) * 100.
		totalResources := max(len(findings), 1)
		score := (1.0 - float64(len(findings))/float64(totalResources)) * 100
		if len(findings) == 0 {
			score = 100.0
		}

		// Delta and trajectory.
		var delta float64
		trajectory := trajectoryStable
		if es, ok := earlierScores[t.ID]; ok {
			delta = score - es
		} else if len(findings) == 0 && earlierScores != nil {
			delta = 0 // no findings then or now
		}
		if delta >= trajectoryThreshold {
			trajectory = trajectoryImproving
		} else if delta <= -trajectoryThreshold {
			trajectory = trajectoryRegressing
		}

		// Count critical.
		critical := 0
		slaTotal := 0
		slaWithin := 0
		var totalDwell float64
		for j := range findings {
			f := &findings[j]
			if strings.EqualFold(f.ControlSeverity.String(), "critical") {
				critical++
			}
			if f.SLADeadlineHours != nil {
				slaTotal++
				if !f.SLABreached {
					slaWithin++
				}
			}
			totalDwell += f.Evidence.UnsafeDurationHours
		}

		mttr := 0.0
		if len(findings) > 0 {
			mttr = totalDwell / float64(len(findings))
		}

		slaPct := 100.0
		if slaTotal > 0 {
			slaPct = float64(slaWithin) / float64(slaTotal) * 100
		}

		if regressionOnly && trajectory != trajectoryRegressing {
			continue
		}

		trends = append(trends, TeamTrend{
			ID:           t.ID,
			Name:         t.DisplayName,
			Contact:      t.Contact,
			PostureScore: score,
			ScoreDelta:   delta,
			Trajectory:   trajectory,
			MTTRHours:    mttr,
			SLACompPct:   slaPct,
			OpenFindings: len(findings),
			CriticalOpen: critical,
		})
	}

	// Also include "unassigned" if there are unassigned findings.
	if teamFilter == "" {
		if uf := teamFindings["unassigned"]; len(uf) > 0 {
			trends = append(trends, TeamTrend{
				ID:           "unassigned",
				Name:         "Unassigned",
				PostureScore: 0,
				Trajectory:   trajectoryStable,
				OpenFindings: len(uf),
			})
		}
	}

	// Sort by score descending.
	sort.Slice(trends, func(i, j int) bool {
		return trends[i].PostureScore > trends[j].PostureScore
	})

	// Summary.
	summary := &TeamTrendSummary{TeamsTracked: len(trends)}
	for i := range trends {
		switch trends[i].Trajectory {
		case trajectoryImproving:
			summary.TeamsImproving++
		case trajectoryStable:
			summary.TeamsStable++
		case trajectoryRegressing:
			summary.TeamsRegressing++
		}
	}

	return trends, summary
}

// computeRollup aggregates team trends for a hierarchy group.
func computeRollup(trends []TeamTrend, group *teams.HierarchyGroup) *RollupResult {
	if group == nil {
		return nil
	}
	memberSet := make(map[string]bool, len(group.Teams))
	for _, tid := range group.Teams {
		memberSet[tid] = true
	}

	var totalScore, totalMTTR float64
	var totalSLAWithin, totalSLAAll int
	var openFindings, criticalOpen, count int
	for i := range trends {
		t := &trends[i]
		if !memberSet[t.ID] {
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

	return &RollupResult{
		GroupID:      group.ID,
		GroupName:    group.Name,
		PostureScore: totalScore / float64(count),
		MTTRHours:    totalMTTR / float64(count),
		SLACompPct:   slaPct,
		OpenFindings: openFindings,
		CriticalOpen: criticalOpen,
	}
}

// renderExecutiveSummary writes a plain-text paragraph for board reporting.
func renderExecutiveSummary(w io.Writer, r *TrendReport) error { //nolint:unparam // error return for format-dispatch consistency
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

	if r.TeamSummary != nil {
		ts := r.TeamSummary
		fmt.Fprintf(w, " %d of %d teams are improving, %d are stable, %d require attention.\n",
			ts.TeamsImproving, ts.TeamsTracked, ts.TeamsStable, ts.TeamsRegressing)

		// Attention required: regressing teams.
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			if t.Trajectory != trajectoryRegressing {
				continue
			}
			name := t.Name
			if name == "" {
				name = t.ID
			}
			fmt.Fprintf(w, "\nATTENTION REQUIRED: %s (score %.1f, %+.1f). %d critical findings open.",
				name, t.PostureScore, t.ScoreDelta, t.CriticalOpen)
			if t.Contact != "" {
				fmt.Fprintf(w, " Contact: %s.", t.Contact)
			}
			fmt.Fprintln(w)
		}

		// Top performer: best improving team.
		var best *TeamTrend
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			if t.Trajectory == trajectoryImproving {
				if best == nil || t.ScoreDelta > best.ScoreDelta {
					best = t
				}
			}
		}
		if best != nil {
			name := best.Name
			if name == "" {
				name = best.ID
			}
			fmt.Fprintf(w, "\nTop performer: %s (score %.1f, %+.1f, MTTR %.1fh, %.0f%% SLA compliance).\n",
				name, best.PostureScore, best.ScoreDelta, best.MTTRHours, best.SLACompPct)
		}
	} else {
		fmt.Fprintln(w)
	}

	return nil
}
