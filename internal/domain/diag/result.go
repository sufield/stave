package diag

import (
	"fmt"
	"strings"
)

// Result groups diagnostic issues and provides aggregate inquiry helpers.
type Result struct {
	Issues []Issue `json:"issues"`
}

// NewResult creates an empty diagnostic result.
func NewResult() *Result {
	return &Result{Issues: make([]Issue, 0)}
}

// Add appends a single issue.
func (r *Result) Add(issue Issue) {
	if r == nil {
		return
	}
	r.Issues = append(r.Issues, issue)
}

// AddAll appends multiple issues.
func (r *Result) AddAll(issues []Issue) {
	if r == nil || len(issues) == 0 {
		return
	}
	r.Issues = append(r.Issues, issues...)
}

// Merge appends issues from another result.
func (r *Result) Merge(other *Result) {
	if r == nil || other == nil || len(other.Issues) == 0 {
		return
	}
	r.Issues = append(r.Issues, other.Issues...)
}

// HasErrors reports whether any issue is error severity.
func (r *Result) HasErrors() bool {
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
func (r *Result) HasWarnings() bool {
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
func (r *Result) Errors() []Issue {
	return r.filter(SignalError)
}

// Warnings returns only warning-level issues.
func (r *Result) Warnings() []Issue {
	return r.filter(SignalWarn)
}

func (r *Result) filter(signal Signal) []Issue {
	if r == nil {
		return nil
	}
	filtered := make([]Issue, 0, len(r.Issues))
	for _, issue := range r.Issues {
		if issue.Signal == signal {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

// Error implements error for interoperability with Go error handling.
func (r *Result) Error() string {
	if r == nil {
		return "validation failed: 0 errors, 0 warnings"
	}
	base := fmt.Sprintf(
		"validation failed: %d errors, %d warnings",
		len(r.Errors()),
		len(r.Warnings()),
	)

	first := r.firstIssueSummary()
	if first == "" {
		return base
	}
	return base + ": " + first
}

func (r *Result) firstIssueSummary() string {
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
