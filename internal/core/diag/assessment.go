package diag

import (
	"fmt"
	"strings"
)

// Assessment groups security findings and provides aggregate analysis helpers.
// It represents the final collection of security issues identified during a scan.
type Assessment struct { //nolint:errname // Assessment is a findings collection, not inherently an error — implements error for CI pipeline gating
	Findings []Finding `json:"findings"`
}

// NewAssessment initializes a security assessment with an empty findings slice.
// Using make([]Finding, 0) ensures the JSON output is an empty array [] rather than null.
func NewAssessment() *Assessment {
	return &Assessment{Findings: make([]Finding, 0)}
}

// Record adds a single security finding to the assessment.
func (a *Assessment) Record(f Finding) {
	if a == nil {
		return
	}
	a.Findings = append(a.Findings, f)
}

// RecordAll appends multiple security findings to the assessment.
func (a *Assessment) RecordAll(fs []Finding) {
	if a == nil || len(fs) == 0 {
		return
	}
	a.Findings = append(a.Findings, fs...)
}

// Merge combines findings from another assessment into this one.
func (a *Assessment) Merge(other *Assessment) {
	if a == nil || other == nil || len(other.Findings) == 0 {
		return
	}
	a.Findings = append(a.Findings, other.Findings...)
}

// Failed reports whether the assessment contains any findings with Error severity.
// This is typically used to determine a non-zero exit code in CLI tools.
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

// HasWarnings reports whether the assessment contains any findings with Warning severity.
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

// Errors returns a subset of findings that have Error-level severity.
func (a *Assessment) Errors() []Finding {
	return a.filter(SeverityError)
}

// Warnings returns a subset of findings that have Warning-level severity.
func (a *Assessment) Warnings() []Finding {
	return a.filter(SeverityWarn)
}

func (a *Assessment) filter(sev DiagLevel) []Finding {
	if a == nil {
		return nil
	}
	filtered := make([]Finding, 0)
	for _, f := range a.Findings {
		if f.Severity == sev {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// Error implements the standard error interface.
// This allows an Assessment to be returned as an error, making it easy to
// break CI/CD pipelines when security violations are found.
func (a *Assessment) Error() string {
	if a == nil || len(a.Findings) == 0 {
		return "security assessment passed: no issues identified"
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
		return summary + " | First Finding: " + first
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
