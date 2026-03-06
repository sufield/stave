package diagnosis

// Run orchestrates the diagnostic flow.
func Run(input Input) Report {
	summary := input.Summarize()
	report := Report{Summary: summary}

	if len(input.Findings) == 0 {
		s := newSession(input, summary.TotalResources)
		report.Entries = append(report.Entries, s.diagnoseNoViolations()...)
		report.Entries = append(report.Entries, s.diagnoseEmptyFindings()...)
	} else {
		report.Entries = append(report.Entries, diagnoseViolationEvidence(input, summary.MaxCapturedAt)...)
	}

	return report
}
