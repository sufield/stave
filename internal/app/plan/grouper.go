// Package plan produces team-routed remediation plans from assessment findings.
package plan

import (
	"sort"
	"strings"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
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

// PlanFinding is a finding formatted for a remediation plan.
type PlanFinding struct {
	Rank              int               `json:"rank"`
	ControlID         string            `json:"control_id"`
	ControlName       string            `json:"control_name"`
	Severity          string            `json:"severity"`
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
	if v, ok := kernel.SeverityOrder[strings.ToLower(input.MinSeverity)]; ok {
		minSev = v
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
		sev := kernel.SeverityOrder[strings.ToLower(f.ControlSeverity.String())]
		if sev > minSev {
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
		si := kernel.SeverityOrder[strings.ToLower(items[i].finding.ControlSeverity.String())]
		sj := kernel.SeverityOrder[strings.ToLower(items[j].finding.ControlSeverity.String())]
		if si != sj {
			return si < sj
		}
		return items[i].finding.Evidence.UnsafeDurationHours > items[j].finding.Evidence.UnsafeDurationHours
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
		Severity:         f.ControlSeverity.String(),
		AssetID:          string(f.AssetID),
		DwellHours:       f.Evidence.UnsafeDurationHours,
		SLABreached:      f.SLABreached,
		SLADeadlineHours: f.SLADeadlineHours,
		OverdueHours:     f.SLAOverdueHours,
	}
	if f.RemediationSpec.Action != "" {
		pf.RemediationAction = f.RemediationSpec.Action
	}
	if len(f.ControlCompliance) > 0 {
		pf.Compliance = make(map[string]string, len(f.ControlCompliance))
		for fw, cite := range f.ControlCompliance {
			pf.Compliance[string(fw)] = cite
		}
	}
	return pf
}

func computeSummary(findings []PlanFinding) TeamSummary {
	var s TeamSummary
	s.Total = len(findings)
	slaTotal := 0
	slaWithin := 0
	for i := range findings {
		f := &findings[i]
		switch strings.ToLower(f.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		}
		if f.SLADeadlineHours != nil {
			slaTotal++
			if !f.SLABreached {
				slaWithin++
			} else {
				s.SLABreached++
			}
		}
	}
	if slaTotal > 0 {
		s.SLACompPct = float64(slaWithin) / float64(slaTotal) * 100
	} else {
		s.SLACompPct = 100
	}
	return s
}
