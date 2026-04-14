package evidence

// MapVerdict translates an assessment engine verdict string to an
// EvidenceVerdict. Uses string matching (not importing the evaluation
// package) to keep the evidence package dependency-free within core.
func MapVerdict(v string) EvidenceVerdict {
	switch v {
	case "VIOLATION":
		return VerdictFail
	case "PASS":
		return VerdictPass
	case "INCONCLUSIVE":
		return VerdictIncomplete
	case "NOT_APPLICABLE", "SKIPPED":
		return VerdictNotApplicable
	default:
		return VerdictNotApplicable
	}
}
