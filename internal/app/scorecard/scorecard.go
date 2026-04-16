// Package scorecard produces a multi-framework compliance scorecard.
package scorecard

import (
	"sort"
	"strings"

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
		total := 0
		failing := 0
		critical := 0
		var topFailing string

		seen := make(map[string]bool)
		for i := range findings {
			f := &findings[i]
			if _, ok := f.ControlCompliance[fwKey]; !ok {
				continue
			}
			cid := string(f.ControlID)
			if !seen[cid] {
				seen[cid] = true
				total++
				failing++
				if strings.EqualFold(f.ControlSeverity.String(), "critical") {
					critical++
					if topFailing == "" {
						topFailing = cid
					}
				}
				if topFailing == "" {
					topFailing = cid
				}
			}
		}

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
	sort.Slice(report.Frameworks, func(i, j int) bool {
		return report.Frameworks[i].ReadinessPct < report.Frameworks[j].ReadinessPct
	})

	return report
}
