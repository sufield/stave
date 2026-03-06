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
	filtered.Entries = make([]diagnosis.Entry, 0, len(report.Entries))
	for _, d := range report.Entries {
		if diagnoseDiagnosisMatchesFilter(d, caseSet, needle) {
			filtered.Entries = append(filtered.Entries, d)
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

func diagnoseDiagnosisMatchesFilter(d diagnosis.Entry, caseSet map[string]struct{}, needle string) bool {
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
