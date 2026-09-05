// Package scorecard produces a multi-framework compliance scorecard.
package scorecard

import (
	"cmp"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// FrameworkScore holds readiness data for one framework.
type FrameworkScore struct {
	Framework        policy.ComplianceFramework `json:"framework"`
	ReadinessPct     float64                    `json:"readiness_pct"`
	ControlsTotal    int                        `json:"controls_total"`
	ControlsPassing  int                        `json:"controls_passing"`
	ControlsFailing  int                        `json:"controls_failing"`
	CriticalFindings int                        `json:"critical_findings"`
	NextAction       string                     `json:"next_action,omitempty"`
}

// Report holds the full scorecard.
type Report struct {
	GeneratedAt string           `json:"generated_at"`
	Frameworks  []FrameworkScore `json:"frameworks"`
}

// Compute builds a scorecard across multiple frameworks.
func Compute(findings []remediation.Finding, frameworks []policy.ComplianceFramework) *Report {
	report := &Report{}

	for _, fw := range frameworks {
		var perControl remediation.FindingSet
		bestFinding := make(map[kernel.ControlID]remediation.Finding)
		for i := range findings {
			f := &findings[i]
			if !hasFrameworkCompliance(f, fw) {
				continue
			}
			cid := f.ControlID
			existing, ok := bestFinding[cid]
			if !ok || f.ControlSeverity > existing.ControlSeverity {
				bestFinding[cid] = *f
			}
		}
		seen := make(map[kernel.ControlID]struct{})
		for i := range findings {
			f := &findings[i]
			if !hasFrameworkCompliance(f, fw) {
				continue
			}
			cid := f.ControlID
			if _, ok := seen[cid]; ok {
				continue
			}
			seen[cid] = struct{}{}
			perControl = append(perControl, bestFinding[cid])
		}
		slices.SortFunc(perControl, func(a, b remediation.Finding) int {
			if n := b.ControlSeverity.Compare(a.ControlSeverity); n != 0 {
				return n
			}
			return cmp.Compare(string(a.ControlID), string(b.ControlID))
		})
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

		readiness := 100.0
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
		if n := cmp.Compare(a.ReadinessPct, b.ReadinessPct); n != 0 {
			return n
		}
		return cmp.Compare(a.Framework, b.Framework)
	})

	return report
}

func hasFrameworkCompliance(f *remediation.Finding, target policy.ComplianceFramework) bool {
	targetStr := string(target)
	for fw := range f.ControlCompliance {
		fwStr := string(fw)
		if strings.EqualFold(fwStr, targetStr) || strings.EqualFold(strings.ReplaceAll(fwStr, "-", "_"), strings.ReplaceAll(targetStr, "-", "_")) {
			return true
		}
	}
	return false
}
