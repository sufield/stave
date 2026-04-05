package diagnosis

// Explain orchestrates the diagnostic flow to provide context on the current results.
// It detects why findings might be missing or provides evidence for existing ones.
func Explain(input Input) Report {
	summary := input.Summarize()
	s := newSession(input, summary.TotalAssets)

	var issues []Insight
	if len(input.Findings) == 0 {
		issues = s.diagnoseMissingFindings()
	} else {
		issues = s.diagnoseExistingFindings(summary.MaxCapturedAt)
	}

	return Report{
		Summary: summary,
		Issues:  issues,
	}
}
