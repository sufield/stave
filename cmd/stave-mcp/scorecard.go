package main

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"sort"
	"text/template"

	"github.com/sufield/stave/pkg/stave"
)

// scorecardView is the escape-safe data the scorecard template
// renders. As with the dashboard, every free-text field is
// HTML-escaped during preparation and numbers/enums are produced
// here, so text/template is safe. This renderer is intentionally
// independent of dashboard.go — it shares only the brand color
// constants, not rendering logic.
type scorecardView struct {
	Frameworks []fwView
	Compare    []compareRow
}

type fwView struct {
	TabID        string
	FrameworkID  string
	Name         string
	Version      string
	Percent      string
	PercentColor string
	Met          int
	NotMet       int
	NotEval      int
	Total        int
	Requirements []reqView
	Active       bool
}

type reqView struct {
	ID        string
	Title     string
	Status    string
	Class     string
	Findings  int
	CanExpand bool
	Fails     []failCtl
}

type failCtl struct {
	ControlID string
	Asset     string
	Name      string
}

type compareRow struct {
	Name       string
	Pct        float64
	PercentStr string
	Width      string
	Color      string
}

// renderScorecard returns a complete, self-contained HTML compliance
// scorecard for one or more framework assessments — framework tabs, a
// per-framework requirement breakdown with expandable failures, and a
// cross-framework comparison. All CSS/JS inline; no network, no
// storage.
func renderScorecard(reports []*stave.ComplianceReport) (string, error) {
	if len(reports) == 0 {
		return "", errors.New("renderScorecard: no framework reports")
	}
	view := buildScorecardView(reports)

	tmpl, err := template.New("scorecard").Parse(scorecardHTML)
	if err != nil {
		return "", fmt.Errorf("parse scorecard template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		return "", fmt.Errorf("render scorecard: %w", err)
	}
	return buf.String(), nil
}

// buildScorecardView projects per-framework ComplianceReports into the
// escape-safe view model. Requirement status is derived from the
// report's own methods (IsMet / IsNotEvaluated) so this renderer needs
// no internal package import.
func buildScorecardView(reports []*stave.ComplianceReport) scorecardView {
	var sv scorecardView
	for i, r := range reports {
		fw := fwView{
			TabID:        fmt.Sprintf("fw%d", i),
			FrameworkID:  html.EscapeString(r.FrameworkID),
			Name:         html.EscapeString(r.FrameworkName),
			Version:      html.EscapeString(r.FrameworkVersion),
			Percent:      fmt.Sprintf("%.0f", r.CoveragePercent),
			PercentColor: percentColor(r.CoveragePercent),
			Met:          r.MetCount,
			NotMet:       r.NotMetCount,
			NotEval:      r.NotEvaluatedCount,
			Total:        r.TotalRequirements,
			Active:       i == 0,
		}
		for j := range r.Requirements {
			ra := &r.Requirements[j]
			status, class, canExpand := "PASS", "pass", false
			switch {
			case ra.IsNotEvaluated():
				status, class = "N/A", "na"
			case !ra.IsMet():
				status, class, canExpand = "FAIL", "fail", true
			}
			rv := reqView{
				ID:        html.EscapeString(ra.RequirementID),
				Title:     html.EscapeString(ra.Description),
				Status:    status,
				Class:     class,
				Findings:  ra.FailCount,
				CanExpand: canExpand,
			}
			if canExpand {
				for _, e := range ra.Evidence {
					if e.IsFail() {
						rv.Fails = append(rv.Fails, failCtl{
							ControlID: html.EscapeString(e.ControlID),
							Asset:     html.EscapeString(e.ResourceARN),
							Name:      html.EscapeString(e.ControlName),
						})
					}
				}
			}
			fw.Requirements = append(fw.Requirements, rv)
		}
		sv.Frameworks = append(sv.Frameworks, fw)
		sv.Compare = append(sv.Compare, compareRow{
			Name:       html.EscapeString(r.FrameworkName),
			Pct:        r.CoveragePercent,
			PercentStr: fmt.Sprintf("%.0f", r.CoveragePercent),
			Width:      fmt.Sprintf("%.2f", r.CoveragePercent),
			Color:      percentColor(r.CoveragePercent),
		})
	}
	// Lowest compliance first — highest remediation priority on top.
	sort.SliceStable(sv.Compare, func(i, j int) bool {
		return sv.Compare[i].Pct < sv.Compare[j].Pct
	})
	return sv
}

// percentColor maps a compliance percentage to a color: green > 90,
// amber 70–90, red < 70.
func percentColor(p float64) string {
	switch {
	case p > 90:
		return colorGreen
	case p >= 70:
		return colorAmber
	default:
		return colorRed
	}
}
