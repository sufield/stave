package diag

import (
	"fmt"
	"strings"
)

// Report groups diagnostic issues and provides aggregate inquiry helpers.
type Report struct {
	Issues []Diagnostic `json:"issues"`
}

// NewResult creates an empty diagnostic result.
func NewResult() *Report {
	return &Report{Issues: make([]Diagnostic, 0)}
}

// Add appends a single issue.
func (r *Report) Add(issue Diagnostic) {
	if r == nil {
		return
	}
	r.Issues = append(r.Issues, issue)
}

// AddAll appends multiple issues.
func (r *Report) AddAll(issues []Diagnostic) {
	if r == nil || len(issues) == 0 {
		return
	}
	r.Issues = append(r.Issues, issues...)
}

// Merge appends issues from another result.
func (r *Report) Merge(other *Report) {
	if r == nil || other == nil || len(other.Issues) == 0 {
		return
	}
	r.Issues = append(r.Issues, other.Issues...)
}

// HasErrors reports whether any issue is error severity.
func (r *Report) HasErrors() bool {
	if r == nil {
		return false
	}
	for _, issue := range r.Issues {
		if issue.Signal == SignalError {
			return true
		}
	}
	return false
}

// HasWarnings reports whether any issue is warning severity.
func (r *Report) HasWarnings() bool {
	if r == nil {
		return false
	}
	for _, issue := range r.Issues {
		if issue.Signal == SignalWarn {
			return true
		}
	}
	return false
}

// Errors returns only error-level issues.
func (r *Report) Errors() []Diagnostic {
	return r.filter(SignalError)
}

// Warnings returns only warning-level issues.
func (r *Report) Warnings() []Diagnostic {
	return r.filter(SignalWarn)
}

func (r *Report) filter(signal Signal) []Diagnostic {
	if r == nil {
		return nil
	}
	filtered := make([]Diagnostic, 0, len(r.Issues))
	for _, issue := range r.Issues {
		if issue.Signal == signal {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

// Error implements error for interoperability with Go error handling.
func (r *Report) Error() string {
	if r == nil || len(r.Issues) == 0 {
		return "validation failed: 0 errors, 0 warnings"
	}

	var errs, warns int
	for _, iss := range r.Issues {
		switch iss.Signal {
		case SignalError:
			errs++
		case SignalWarn:
			warns++
		}
	}

	summary := fmt.Sprintf("validation failed: %d errors, %d warnings", errs, warns)
	if first := r.firstIssueSummary(); first != "" {
		return summary + ": " + first
	}
	return summary
}

func (r *Report) firstIssueSummary() string {
	if r == nil || len(r.Issues) == 0 {
		return ""
	}
	issue := r.Issues[0]

	path, hasPath := issue.Evidence.Get("path")
	msg := strings.TrimSpace(issue.Message)
	switch {
	case msg != "" && hasPath:
		return fmt.Sprintf("%s (%s)", msg, path)
	case msg != "":
		return msg
	case hasPath:
		return path
	default:
		return string(issue.Code)
	}
}
