package diagnose

import (
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
)

func filterDiagnosisReport(
	report *diagnosis.Report,
	cases []string,
	signalContains string,
) *diagnosis.Report {
	if report == nil {
		return nil
	}
	caseSet := diagnoseCaseSet(cases)
	needle := strings.ToLower(strings.TrimSpace(signalContains))
	if len(caseSet) == 0 && needle == "" {
		return report
	}
	filtered := *report
	filtered.Issues = make([]diagnosis.Issue, 0, len(report.Issues))
	for _, d := range report.Issues {
		if diagnoseDiagnosisMatchesFilter(d, caseSet, needle) {
			filtered.Issues = append(filtered.Issues, d)
		}
	}
	return &filtered
}

func diagnoseCaseSet(cases []string) map[string]struct{} {
	caseSet := map[string]struct{}{}
	for _, c := range cases {
		trimmed := strings.TrimSpace(c)
		if trimmed == "" {
			continue
		}
		caseSet[trimmed] = struct{}{}
	}
	return caseSet
}

func diagnoseDiagnosisMatchesFilter(d diagnosis.Issue, caseSet map[string]struct{}, needle string) bool {
	if len(caseSet) > 0 {
		if _, ok := caseSet[string(d.Case)]; !ok {
			return false
		}
	}
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(d.Signal), needle)
}
