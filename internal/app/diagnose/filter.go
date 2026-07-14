package diagnose

import (
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/util/strutil"
)

// Filter defines the criteria for narrowing down a diagnostic report.
type Filter struct {
	Cases          []string
	SignalContains string
}

// IsEmpty returns true if no filtering criteria have been provided.
func (f Filter) IsEmpty() bool {
	return len(f.Cases) == 0 && f.SignalContains == ""
}

func toLowerTrim(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	trimmed := s[start:end]
	needsLower := false
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] >= 'A' && trimmed[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		return strings.ToLower(trimmed)
	}
	return trimmed
}

// Apply applies the filter criteria to a diagnostic report and returns
// a new report containing only the matching issues.
func (f Filter) Apply(report *diagnosis.Report) *diagnosis.Report {
	if report == nil || f.IsEmpty() {
		return report
	}

	caseSet := make(map[string]struct{}, len(f.Cases))
	for _, c := range f.Cases {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			caseSet[trimmed] = struct{}{}
		}
	}

	needle := toLowerTrim(f.SignalContains)

	filtered := *report
	filtered.Issues = make([]diagnosis.Insight, 0, len(report.Issues))

	for _, issue := range report.Issues {
		if matchesFilter(issue, caseSet, needle) {
			filtered.Issues = append(filtered.Issues, issue)
		}
	}

	return &filtered
}

func matchesFilter(issue diagnosis.Insight, caseSet map[string]struct{}, needle string) bool {
	if len(caseSet) > 0 {
		if _, ok := caseSet[string(issue.Case)]; !ok {
			return false
		}
	}
	if needle != "" {
		if !strutil.ContainsFold(issue.Signal, needle) {
			return false
		}
	}
	return true
}
