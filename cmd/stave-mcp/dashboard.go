package main

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"text/template"

	"github.com/sufield/stave/pkg/stave"
)

// Stave brand palette — kept in one place so the template and any
// future renderers stay consistent.
const (
	colorCritical = "#EF4444"
	colorHigh     = "#F97316"
	colorMedium   = "#FBBF24"
	colorLow      = "#3B82F6"
	colorGreen    = "#22C55E"
	colorAmber    = "#FBBF24"
	colorRed      = "#EF4444"
)

// gaugeCircumference is 2·π·r for the gauge's r=80 ring. The filled
// arc length is score/100 of this; the template draws it as a
// stroke-dasharray.
const gaugeCircumference = 502.65

// dashboardView is the prepared, escape-safe data the HTML template
// renders. Every free-text field (control IDs, asset IDs, messages)
// is HTML-escaped during preparation; numeric and enum fields are
// produced by this package and are safe by construction. That is why
// text/template (not html/template) is used: escaping is done once,
// explicitly, at the data boundary.
type dashboardView struct {
	Score         int
	ScoreColor    string
	GaugeDash     string
	SecurityState string
	Findings      int
	Assets        int
	Snapshots     int
	EvaluatedAt   string
	Severities    []sevBucket
	Rows          []findingRow
	SLABreaches   int
	SLAItems      []slaItem
	TopN          int
}

type sevBucket struct {
	Label string
	Count int
	Color string
	Pct   string
	Has   bool
}

type findingRow struct {
	Severity  string
	SevRank   int
	Color     string
	ControlID string
	Asset     string
	Message   string
	Extra     bool
}

type slaItem struct {
	ControlID   string
	OverdueDays string
}

// renderDashboard returns a complete, self-contained HTML document
// for the assessment — all CSS and JS inline, no network, no
// storage. It is safe to write to a file and open in any browser, or
// to hand to an MCP client that renders HTML.
func renderDashboard(a *stave.Assessment) (string, error) {
	score := 0
	if sr, err := stave.Score(context.Background(), stave.ScoreConfig{Assessment: a}); err == nil {
		score = sr.ScoreInt
	}
	view := buildDashboardView(a, score)

	tmpl, err := template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		return "", fmt.Errorf("parse dashboard template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		return "", fmt.Errorf("render dashboard: %w", err)
	}
	return buf.String(), nil
}

// buildDashboardView projects an Assessment into the escape-safe view
// model. rankBySeverity, severityRank, and findingMessage are shared
// with the text formatter (format.go).
func buildDashboardView(a *stave.Assessment, score int) dashboardView {
	v := dashboardView{
		Score:         score,
		ScoreColor:    scoreColor(score),
		SecurityState: string(a.Status),
		Findings:      a.Summary.Violations,
		Assets:        a.Summary.TotalAssets,
		Snapshots:     a.Run.Snapshots,
		EvaluatedAt:   a.Run.Now.Format("2006-01-02 15:04:05 MST"),
		SLABreaches:   a.SLABreaches,
		TopN:          20,
	}

	filled := float64(score) / 100 * gaugeCircumference
	v.GaugeDash = fmt.Sprintf("%.2f %.2f", filled, gaugeCircumference-filled)

	counts := a.CountBySeverity()
	total := 0
	for _, n := range counts {
		total += n
	}
	for _, o := range []struct {
		sev   stave.Severity
		label string
		color string
	}{
		{stave.SeverityCritical, "CRITICAL", colorCritical},
		{stave.SeverityHigh, "HIGH", colorHigh},
		{stave.SeverityMedium, "MEDIUM", colorMedium},
		{stave.SeverityLow, "LOW", colorLow},
	} {
		n := counts[o.sev]
		pct := 0.0
		if total > 0 {
			pct = float64(n) / float64(total) * 100
		}
		v.Severities = append(v.Severities, sevBucket{
			Label: o.label, Count: n, Color: o.color,
			Pct: fmt.Sprintf("%.2f", pct), Has: n > 0,
		})
	}

	ranked := rankBySeverity(a.Findings)
	for i := range ranked {
		f := &ranked[i]
		v.Rows = append(v.Rows, findingRow{
			Severity:  string(f.Severity),
			SevRank:   severityRank(f.Severity),
			Color:     severityColor(f.Severity),
			ControlID: html.EscapeString(string(f.ControlID)),
			Asset:     html.EscapeString(string(f.AssetID)),
			Message:   html.EscapeString(findingMessage(f)),
			Extra:     i >= v.TopN,
		})
	}

	for i := range a.Findings {
		f := &a.Findings[i]
		if f.SLABreached && f.SLAOverdueHours != nil {
			v.SLAItems = append(v.SLAItems, slaItem{
				ControlID:   html.EscapeString(string(f.ControlID)),
				OverdueDays: fmt.Sprintf("%.1f", *f.SLAOverdueHours/24),
			})
		}
	}

	return v
}

// scoreColor maps a posture score to a gauge color: green > 80,
// amber 50–80, red < 50.
func scoreColor(score int) string {
	switch {
	case score > 80:
		return colorGreen
	case score >= 50:
		return colorAmber
	default:
		return colorRed
	}
}

// severityColor maps a finding severity to its palette color.
func severityColor(s stave.Severity) string {
	switch s {
	case stave.SeverityCritical:
		return colorCritical
	case stave.SeverityHigh:
		return colorHigh
	case stave.SeverityMedium:
		return colorMedium
	default:
		return colorLow
	}
}
