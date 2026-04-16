package trend

import (
	"sort"
	"strings"

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
