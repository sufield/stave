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

// ReadinessPercentage represents a compliance readiness score between 0.0 and 100.0 percent.
type ReadinessPercentage float64

// Value returns the raw float64 value of the readiness percentage.
func (r ReadinessPercentage) Value() float64 {
	return float64(r)
}

// Clamp returns the readiness percentage constrained to the valid range [0.0, 100.0].
func (r ReadinessPercentage) Clamp() ReadinessPercentage {
	if r < 0 {
		return 0
	}
	if r > 100 {
		return 100
	}
	return r
}

// FrameworkScore holds readiness data for one framework.
type FrameworkScore struct {
	Framework        policy.ComplianceFramework `json:"framework"`
	ReadinessPct     ReadinessPercentage        `json:"readiness_pct"`
	ControlsTotal    int                        `json:"controls_total"`
	ControlsPassing  int                        `json:"controls_passing"`
	ControlsFailing  int                        `json:"controls_failing"`
	CriticalFindings int                        `json:"critical_findings"`
	NextAction       kernel.ControlID           `json:"next_action,omitempty"`
}

// IsAuditReady reports whether the framework readiness meets or exceeds 90% with zero critical findings.
func (fs FrameworkScore) IsAuditReady() bool {
	return fs.ReadinessPct >= 90.0 && fs.CriticalFindings == 0
}

// IsPassing reports whether all controls evaluated in this framework passed.
func (fs FrameworkScore) IsPassing() bool {
	return fs.ControlsTotal > 0 && fs.ControlsFailing == 0
}

// HasFailing reports whether any controls are failing in this framework.
func (fs FrameworkScore) HasFailing() bool {
	return fs.ControlsFailing > 0
}

// HasCritical reports whether there are critical findings in this framework.
func (fs FrameworkScore) HasCritical() bool {
	return fs.CriticalFindings > 0
}

// HasNextAction reports whether a priority next remediation control is identified.
func (fs FrameworkScore) HasNextAction() bool {
	return fs.NextAction != ""
}

// PassingRatio returns the fraction of passing controls over total controls (0.0 to 1.0).
func (fs FrameworkScore) PassingRatio() float64 {
	if fs.ControlsTotal <= 0 {
		return 1.0
	}
	return float64(fs.ControlsPassing) / float64(fs.ControlsTotal)
}

// FailingRatio returns the fraction of failing controls over total controls (0.0 to 1.0).
func (fs FrameworkScore) FailingRatio() float64 {
	if fs.ControlsTotal <= 0 {
		return 0.0
	}
	return float64(fs.ControlsFailing) / float64(fs.ControlsTotal)
}

// FrameworkScores is a domain collection of FrameworkScore items with querying methods.
type FrameworkScores []FrameworkScore

// Len returns the number of framework scores in the collection.
func (fs FrameworkScores) Len() int {
	return len(fs)
}

// IsEmpty reports whether the collection contains no framework scores.
func (fs FrameworkScores) IsEmpty() bool {
	return len(fs) == 0
}

// AuditReady returns the subset of framework scores meeting the audit readiness threshold.
func (fs FrameworkScores) AuditReady() FrameworkScores {
	if len(fs) == 0 {
		return nil
	}
	var out FrameworkScores
	for _, score := range fs {
		if score.IsAuditReady() {
			out = append(out, score)
		}
	}
	return out
}

// WithCritical returns framework scores that contain critical findings.
func (fs FrameworkScores) WithCritical() FrameworkScores {
	if len(fs) == 0 {
		return nil
	}
	var out FrameworkScores
	for _, score := range fs {
		if score.HasCritical() {
			out = append(out, score)
		}
	}
	return out
}

// Frameworks returns the list of compliance frameworks represented in the scores.
func (fs FrameworkScores) Frameworks() ComplianceFrameworks {
	if len(fs) == 0 {
		return nil
	}
	out := make(ComplianceFrameworks, len(fs))
	for i, score := range fs {
		out[i] = score.Framework
	}
	return out
}

// AverageReadiness calculates the mean readiness percentage across all frameworks.
func (fs FrameworkScores) AverageReadiness() ReadinessPercentage {
	if len(fs) == 0 {
		return 100.0
	}
	var total float64
	for _, score := range fs {
		total += score.ReadinessPct.Value()
	}
	return ReadinessPercentage(total / float64(len(fs)))
}

// WorstReadiness returns the framework score with the lowest readiness percentage, or nil if empty.
func (fs FrameworkScores) WorstReadiness() *FrameworkScore {
	if len(fs) == 0 {
		return nil
	}
	worst := &fs[0]
	for i := 1; i < len(fs); i++ {
		if fs[i].ReadinessPct < worst.ReadinessPct {
			worst = &fs[i]
		}
	}
	return worst
}

// ComplianceFrameworks is a domain collection of policy.ComplianceFramework items with query methods.
type ComplianceFrameworks []policy.ComplianceFramework

// Len returns the number of frameworks in the collection.
func (cfs ComplianceFrameworks) Len() int {
	return len(cfs)
}

// Contains reports whether the given framework is present in the collection.
func (cfs ComplianceFrameworks) Contains(fw policy.ComplianceFramework) bool {
	return slices.Contains(cfs, fw)
}

// Report holds the full scorecard.
type Report struct {
	GeneratedAt string          `json:"generated_at"`
	Frameworks  FrameworkScores `json:"frameworks"`
}

// IsEmpty reports whether the report has no framework scores.
func (r *Report) IsEmpty() bool {
	return r == nil || r.Frameworks.IsEmpty()
}

// FrameworkCount returns the number of frameworks in the report.
func (r *Report) FrameworkCount() int {
	if r == nil {
		return 0
	}
	return r.Frameworks.Len()
}

// WorstReadiness returns the framework score with the lowest readiness, or nil if empty.
func (r *Report) WorstReadiness() *FrameworkScore {
	if r == nil {
		return nil
	}
	return r.Frameworks.WorstReadiness()
}

// HasCriticalFindings reports whether any framework has critical findings.
func (r *Report) HasCriticalFindings() bool {
	return r != nil && !r.Frameworks.WithCritical().IsEmpty()
}

// IsAuditReady reports whether all frameworks in the report meet audit readiness (and report is non-empty).
func (r *Report) IsAuditReady() bool {
	if r == nil || r.Frameworks.IsEmpty() {
		return false
	}
	for _, f := range r.Frameworks {
		if !f.IsAuditReady() {
			return false
		}
	}
	return true
}

// Compute builds a scorecard across multiple frameworks.
func Compute(findings []remediation.Finding, frameworks ComplianceFrameworks) *Report {
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
		topFailing := perControl.Headline()

		// Approximate total controls from findings (we only see failures).
		// In practice, the caller would provide control catalog count.
		passing := 0
		if total > 0 {
			passing = 0 // all observed controls are failing
		}

		readiness := ReadinessPercentage(100.0)
		if total > 0 {
			readiness = ReadinessPercentage(float64(passing) / float64(total) * 100)
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
