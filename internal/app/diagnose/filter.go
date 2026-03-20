package diagnose

import (
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
)

// Filter defines the criteria for narrowing down a diagnostic report.
type Filter struct {
	Cases          []string
	SignalContains string
}

// IsEmpty returns true if no filtering criteria have been provided.
func (f Filter) IsEmpty() bool {
	return len(f.Cases) == 0 && strings.TrimSpace(f.SignalContains) == ""
}

// FilterReport applies the filter criteria to a diagnostic report and returns
// a new report containing only the matching issues.
func FilterReport(report *diagnosis.Report, f Filter) *diagnosis.Report {
	if report == nil || f.IsEmpty() {
		return report
	}

	caseSet := make(map[string]struct{}, len(f.Cases))
	for _, c := range f.Cases {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			caseSet[trimmed] = struct{}{}
		}
	}

	needle := strings.ToLower(strings.TrimSpace(f.SignalContains))

	filtered := *report
	filtered.Issues = make([]diagnosis.Issue, 0, len(report.Issues))

	for _, issue := range report.Issues {
		if matchesFilter(issue, caseSet, needle) {
			filtered.Issues = append(filtered.Issues, issue)
		}
	}

	return &filtered
}

func matchesFilter(issue diagnosis.Issue, caseSet map[string]struct{}, needle string) bool {
	if len(caseSet) > 0 {
		if _, ok := caseSet[string(issue.Case)]; !ok {
			return false
		}
	}
	if needle != "" {
		if !strings.Contains(strings.ToLower(issue.Signal), needle) {
			return false
		}
	}
	return true
}
