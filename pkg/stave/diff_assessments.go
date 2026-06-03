package stave

// AssessmentDiff is the result of comparing two evaluation assessments.
// Each finding is classified by its FindingID (a stable hash over
// control + asset).
type AssessmentDiff struct {
	// Added findings are in Current but not in Previous.
	Added []Finding

	// Removed findings were in Previous but are not in Current.
	Removed []Finding

	// Unchanged findings are in both Previous and Current.
	Unchanged []Finding

	// SeverityChanged findings exist in both but with different severity
	// (e.g., a control was re-classified or SLA escalation changed it).
	SeverityChanged []SeverityChange

	// PreviousStatus is the overall status of the previous assessment.
	PreviousStatus Status

	// CurrentStatus is the overall status of the current assessment.
	CurrentStatus Status
}

// SeverityChange records a finding whose severity differs between
// the two assessments.
type SeverityChange struct {
	Finding          Finding
	PreviousSeverity Severity
}

// DiffAssessments compares two evaluation assessments by FindingID and
// returns the added, removed, unchanged, and severity-changed findings.
//
// Both assessments must be non-nil. Passing the same assessment as both
// previous and current returns all findings as Unchanged.
func DiffAssessments(previous, current *Assessment) *AssessmentDiff {
	diff := &AssessmentDiff{
		PreviousStatus: previous.Status,
		CurrentStatus:  current.Status,
	}

	prevByID := make(map[FindingID]Finding, len(previous.Findings))
	for _, f := range previous.Findings {
		prevByID[f.FindingID] = f
	}

	currByID := make(map[FindingID]Finding, len(current.Findings))
	for _, f := range current.Findings {
		currByID[f.FindingID] = f
	}

	for _, f := range current.Findings {
		prev, existed := prevByID[f.FindingID]
		if !existed {
			diff.Added = append(diff.Added, f)
			continue
		}
		if f.Severity != prev.Severity {
			diff.SeverityChanged = append(diff.SeverityChanged, SeverityChange{
				Finding:          f,
				PreviousSeverity: prev.Severity,
			})
			continue
		}
		diff.Unchanged = append(diff.Unchanged, f)
	}

	for _, f := range previous.Findings {
		if _, exists := currByID[f.FindingID]; !exists {
			diff.Removed = append(diff.Removed, f)
		}
	}

	return diff
}
