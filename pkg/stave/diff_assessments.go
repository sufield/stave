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

	prevByID := make(map[FindingID]int, len(previous.Findings))
	for i := range previous.Findings {
		prevByID[previous.Findings[i].FindingID] = i
	}

	currByID := make(map[FindingID]struct{}, len(current.Findings))
	for i := range current.Findings {
		currByID[current.Findings[i].FindingID] = struct{}{}
	}

	for i := range current.Findings {
		f := &current.Findings[i]
		pi, existed := prevByID[f.FindingID]
		if !existed {
			diff.Added = append(diff.Added, *f)
			continue
		}
		if f.Severity != previous.Findings[pi].Severity {
			diff.SeverityChanged = append(diff.SeverityChanged, SeverityChange{
				Finding:          *f,
				PreviousSeverity: previous.Findings[pi].Severity,
			})
			continue
		}
		diff.Unchanged = append(diff.Unchanged, *f)
	}

	for i := range previous.Findings {
		if _, ok := currByID[previous.Findings[i].FindingID]; !ok {
			diff.Removed = append(diff.Removed, previous.Findings[i])
		}
	}

	return diff
}
