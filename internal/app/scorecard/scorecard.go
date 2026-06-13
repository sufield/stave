// Package scorecard produces a multi-framework compliance scorecard.
package scorecard

import (
	"cmp"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// FrameworkScore holds readiness data for one framework.
type FrameworkScore struct {
	Framework        string  `json:"framework"`
	ReadinessPct     float64 `json:"readiness_pct"`
	ControlsTotal    int     `json:"controls_total"`
	ControlsPassing  int     `json:"controls_passing"`
	ControlsFailing  int     `json:"controls_failing"`
	CriticalFindings int     `json:"critical_findings"`
	NextAction       string  `json:"next_action,omitempty"`
}

// Report holds the full scorecard.
type Report struct {
	GeneratedAt string           `json:"generated_at"`
	Frameworks  []FrameworkScore `json:"frameworks"`
}

// Compute builds a scorecard across multiple frameworks.
func Compute(findings []remediation.Finding, frameworks []string) *Report {
	report := &Report{}

	for _, fw := range frameworks {
		fwKey := policy.ComplianceFramework(fw)
		// Reduce to one representative finding per (framework, control)
		// pair so downstream counts are control-level, not finding-
		// level. Routing the unique slice through FindingSet then
		// lets us delegate "how many of these are Critical?" to the
		// domain method instead of branching on the severity here.
		var perControl remediation.FindingSet
		seen := make(map[string]struct{})
		for i := range findings {
			f := &findings[i]
			if _, ok := f.ControlCompliance[fwKey]; !ok {
				continue
			}
			cid := string(f.ControlID)
			if _, ok := seen[cid]; ok {
				continue
			}
			seen[cid] = struct{}{}
			perControl = append(perControl, *f)
		}
		total := len(perControl)
		failing := total
		critical := perControl.CountCritical()
		topFailing := string(perControl.Headline())

		// Approximate total controls from findings (we only see failures).
		// In practice, the caller would provide control catalog count.
		passing := 0
		if total > 0 {
			passing = 0 // all observed controls are failing
		}

		readiness := 0.0
		if total > 0 {
			readiness = float64(passing) / float64(total) * 100
		}

		report.Frameworks = append(report.Frameworks, FrameworkScore{
			Framework:        fw,
			ReadinessPct:     readiness,
			ControlsTotal:    total,
			ControlsPassing:  passing,
			ControlsFailing:  failing,
			CriticalFindings: critical,
			NextAction:       topFailing,
		})
	}

	// Sort by readiness ascending (worst first).
	slices.SortFunc(report.Frameworks, func(a, b FrameworkScore) int {
		return cmp.Compare(a.ReadinessPct, b.ReadinessPct)
	})

	return report
}
