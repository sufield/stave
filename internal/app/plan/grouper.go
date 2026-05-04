// Package plan produces team-routed remediation plans from assessment findings.
package plan

import (
	"sort"

	"github.com/sufield/stave/internal/app/teams"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	corereport "github.com/sufield/stave/internal/core/report"
)

// TeamPlan holds the remediation plan for a single team.
type TeamPlan struct {
	TeamID   string        `json:"team_id"`
	TeamName string        `json:"team_name"`
	Contact  string        `json:"contact,omitempty"`
	Summary  TeamSummary   `json:"summary"`
	Findings []PlanFinding `json:"findings"`
}

// TeamSummary holds aggregate counts for a team.
type TeamSummary struct {
	Total       int     `json:"total_findings"`
	Critical    int     `json:"critical"`
	High        int     `json:"high"`
	Medium      int     `json:"medium"`
	Low         int     `json:"low"`
	SLABreached int     `json:"sla_breached"`
	SLACompPct  float64 `json:"sla_compliance_pct"`
}

// PlanFinding is a finding formatted for a remediation plan. Severity
// is the typed policy.Severity (rendered as the canonical lowercase
// label via its MarshalJSON), so per-tier counters reuse the
// SeverityCounts.Add path that the rest of the report builders use
// instead of reparsing a stringly-typed field.
type PlanFinding struct {
	Rank              int               `json:"rank"`
	ControlID         string            `json:"control_id"`
	ControlName       string            `json:"control_name"`
	Severity          policy.Severity   `json:"severity"`
	AssetID           string            `json:"asset_id"`
	DwellHours        float64           `json:"dwell_hours"`
	SLADeadlineHours  *float64          `json:"sla_deadline_hours,omitempty"`
	SLABreached       bool              `json:"sla_breached"`
	OverdueHours      *float64          `json:"overdue_hours,omitempty"`
	RemediationAction string            `json:"remediation_action,omitempty"`
	Compliance        map[string]string `json:"compliance,omitempty"`
}

// Plan is the complete remediation plan output.
type Plan struct {
	GeneratedAt  string        `json:"generated_at"`
	Assessment   string        `json:"assessment"`
	SLAProfile   string        `json:"sla_profile,omitempty"`
	Teams        []TeamPlan    `json:"teams"`
	Unattributed []PlanFinding `json:"unattributed,omitempty"`
}

// GroupInput holds the data for plan generation.
type GroupInput struct {
	GeneratedAt string
	Assessment  string
	SLAProfile  string
	Findings    []remediation.Finding
	Manifest    *teams.Manifest
	MinSeverity string
	TeamFilter  string
}

// Group attributes findings to teams and produces a Plan.
func Group(input GroupInput) *Plan {
	minSev := 2 // default: medium
	if parsed, err := policy.ParseSeverity(input.MinSeverity); err == nil && parsed != policy.SeverityNone {
		if v, ok := policy.SeverityOrder(parsed); ok {
			minSev = v
		}
	}

	// Attribute findings to teams.
	type attributed struct {
		finding remediation.Finding
		teamID  string
		team    string
		contact string
	}
	var items []attributed
	for i := range input.Findings {
		f := &input.Findings[i]
		if f.SeveritySortRank() > minSev {
			continue
		}
		owner := input.Manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		if input.TeamFilter != "" && owner.TeamID != input.TeamFilter {
			continue
		}
		items = append(items, attributed{
			finding: *f,
			teamID:  owner.TeamID,
			team:    owner.TeamName,
			contact: owner.Contact,
		})
	}

	// Sort by severity DESC, dwell DESC.
	sort.Slice(items, func(i, j int) bool {
		si := items[i].finding.SeveritySortRank()
		sj := items[j].finding.SeveritySortRank()
		if si != sj {
			return si < sj
		}
		return items[i].finding.DwellHours() > items[j].finding.DwellHours()
	})

	// Group by team.
	teamMap := make(map[string]*TeamPlan)
	var teamOrder []string
	var unattributed []PlanFinding

	for i := range items {
		item := &items[i]
		pf := toPlanFinding(&item.finding)

		if item.teamID == "unassigned" {
			unattributed = append(unattributed, pf)
			continue
		}

		tp, exists := teamMap[item.teamID]
		if !exists {
			tp = &TeamPlan{
				TeamID:   item.teamID,
				TeamName: item.team,
				Contact:  item.contact,
			}
			teamMap[item.teamID] = tp
			teamOrder = append(teamOrder, item.teamID)
		}
		pf.Rank = len(tp.Findings) + 1
		tp.Findings = append(tp.Findings, pf)
	}

	// Compute summaries and collect teams in order.
	var teamPlans []TeamPlan
	for _, tid := range teamOrder {
		tp := teamMap[tid]
		tp.Summary = computeSummary(tp.Findings)
		teamPlans = append(teamPlans, *tp)
	}

	return &Plan{
		GeneratedAt:  input.GeneratedAt,
		Assessment:   input.Assessment,
		SLAProfile:   input.SLAProfile,
		Teams:        teamPlans,
		Unattributed: unattributed,
	}
}

func toPlanFinding(f *remediation.Finding) PlanFinding {
	pf := PlanFinding{
		ControlID:        string(f.ControlID),
		ControlName:      f.ControlName,
		Severity:         f.ControlSeverity,
		AssetID:          string(f.AssetID),
		DwellHours:       f.DwellHours(),
		SLABreached:      f.SLABreachedFlag(),
		SLADeadlineHours: f.SLADeadlinePtr(),
		OverdueHours:     f.SLAOverduePtr(),
	}
	if f.RemediationSpec.HasAction() {
		pf.RemediationAction = f.RemediationSpec.Action
	}
	if len(f.ControlCompliance) > 0 {
		pf.Compliance = make(map[string]string, len(f.ControlCompliance))
		for fw, cite := range f.ControlCompliance {
			pf.Compliance[string(fw)] = string(cite)
		}
	}
	return pf
}

func computeSummary(findings []PlanFinding) TeamSummary {
	var s TeamSummary
	s.Total = len(findings)
	slaTotal := 0
	slaWithin := 0
	var counts corereport.SeverityCounts
	for i := range findings {
		f := &findings[i]
		counts.Add(f.Severity)
		if f.SLADeadlineHours != nil {
			slaTotal++
			// Count by SLABreached alone — the previous shape also
			// required OverdueHours to be populated, which dropped
			// breached-but-overdue-not-recorded findings into the
			// within-SLA bucket and inflated the compliance
			// percentage. OverdueHours is a renderer concern
			// (how-long-overdue display), not the authoritative
			// breach signal.
			if f.SLABreached {
				s.SLABreached++
			} else {
				slaWithin++
			}
		}
	}
	s.Critical = counts.Critical
	s.High = counts.High
	s.Medium = counts.Medium
	s.Low = counts.Low
	if slaTotal > 0 {
		s.SLACompPct = float64(slaWithin) / float64(slaTotal) * 100
	} else {
		s.SLACompPct = 100
	}
	return s
}
