package diag

import (
	"fmt"
	"strings"
)

// Assessment groups security findings and provides aggregate analysis helpers.
type Assessment struct {
	Findings []Finding `json:"findings"`
}

// NewAssessment creates an empty security assessment.
func NewAssessment() *Assessment {
	return &Assessment{Findings: make([]Finding, 0)}
}

// Record adds a single security finding to the assessment.
func (a *Assessment) Record(finding Finding) {
	if a == nil {
		return
	}
	a.Findings = append(a.Findings, finding)
}

// RecordAll appends multiple findings.
func (a *Assessment) RecordAll(findings []Finding) {
	if a == nil || len(findings) == 0 {
		return
	}
	a.Findings = append(a.Findings, findings...)
}

// Merge appends findings from another assessment.
func (a *Assessment) Merge(other *Assessment) {
	if a == nil || other == nil || len(other.Findings) == 0 {
		return
	}
	a.Findings = append(a.Findings, other.Findings...)
}

// Failed reports whether any finding has error severity.
func (a *Assessment) Failed() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// HasWarnings reports whether any finding has warning severity.
func (a *Assessment) HasWarnings() bool {
	if a == nil {
		return false
	}
	for _, f := range a.Findings {
		if f.Severity == SeverityWarn {
			return true
		}
	}
	return false
}

// Errors returns only error-level findings.
func (a *Assessment) Errors() []Finding {
	return a.filter(SeverityError)
}

// Warnings returns only warning-level findings.
func (a *Assessment) Warnings() []Finding {
	return a.filter(SeverityWarn)
}

func (a *Assessment) filter(sev Severity) []Finding {
	if a == nil {
		return nil
	}
	filtered := make([]Finding, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Severity == sev {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// Error implements error for interoperability with Go error handling.
func (a *Assessment) Error() string {
	if a == nil || len(a.Findings) == 0 {
		return "security assessment passed: 0 errors, 0 warnings"
	}

	var errs, warns int
	for _, f := range a.Findings {
		switch f.Severity {
		case SeverityError:
			errs++
		case SeverityWarn:
			warns++
		}
	}

	summary := fmt.Sprintf("security assessment failed: %d errors, %d warnings", errs, warns)
	if first := a.firstFindingSummary(); first != "" {
		return summary + ": " + first
	}
	return summary
}

func (a *Assessment) firstFindingSummary() string {
	if a == nil || len(a.Findings) == 0 {
		return ""
	}
	f := a.Findings[0]

	path, hasPath := f.Resource.Get("path")
	msg := strings.TrimSpace(f.Message)
	switch {
	case msg != "" && hasPath:
		return fmt.Sprintf("%s (%s)", msg, path)
	case msg != "":
		return msg
	case hasPath:
		return path
	default:
		return string(f.RuleID)
	}
}
