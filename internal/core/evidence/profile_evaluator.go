package evidence

// EvaluateProfile evaluates an EvidencePackage against a FrameworkProfile,
// producing a ProfileAssessment with per-requirement coverage scores.
// It is a pure function with no side effects.
func EvaluateProfile(pkg *EvidencePackage, profile *FrameworkProfile) *ProfileAssessment {
	result := &ProfileAssessment{
		FrameworkID:       profile.ID,
		FrameworkName:     profile.Name,
		FrameworkVersion:  profile.Version,
		TotalRequirements: len(profile.Requirements),
	}

	for i := range profile.Requirements {
		req := &profile.Requirements[i]
		ra := evaluateRequirement(pkg, req)
		result.Requirements = append(result.Requirements, ra)

		switch ra.Status {
		case RequirementMet:
			result.MetCount++
		case RequirementNotMet:
			result.NotMetCount++
		case RequirementNotEvaluated:
			result.NotEvaluatedCount++
		case RequirementIncomplete:
			result.IncompleteCount++
		}
	}

	if result.TotalRequirements > 0 {
		result.CoveragePercent = float64(result.MetCount) / float64(result.TotalRequirements) * 100
	}

	return result
}

func evaluateRequirement(pkg *EvidencePackage, req *Requirement) RequirementAssessment {
	ra := RequirementAssessment{
		RequirementID: req.ID,
		Description:   req.Description,
		Section:       req.Section,
		TotalControls: len(req.ControlIDs),
	}

	for _, controlID := range req.ControlIDs {
		records := pkg.FindByControlID(controlID)
		if len(records) == 0 {
			continue
		}

		verdict := aggregateControlVerdict(records)
		if verdict == verdictNotEvaluated {
			// All records were NotApplicable — treat as not evaluated.
			continue
		}

		ra.EvaluatedControls++
		ra.Evidence = append(ra.Evidence, records...)

		switch verdict {
		case verdictPassed:
			ra.PassCount++
		case verdictFailed:
			ra.FailCount++
		case verdictIncomplete:
			ra.IncompleteCount++
		}
	}

	ra.Status = determineStatus(ra, req.PassThreshold)

	if ra.EvaluatedControls > 0 {
		ra.CoveragePercent = float64(ra.PassCount) / float64(ra.EvaluatedControls) * 100
	}

	return ra
}

// controlVerdict is the aggregated verdict for a single control across
// all its resource records.
type controlVerdict int

const (
	verdictPassed controlVerdict = iota
	verdictFailed
	verdictIncomplete
	verdictNotEvaluated // all records were NotApplicable
)

// aggregateControlVerdict determines the worst-case verdict for a control
// across all its evidence records. Fail > Incomplete > Pass > NotApplicable.
func aggregateControlVerdict(records []*EvidenceRecord) controlVerdict {
	hasFail := false
	hasIncomplete := false
	hasPass := false

	for _, r := range records {
		switch r.Verdict {
		case VerdictFail:
			hasFail = true
		case VerdictIncomplete:
			hasIncomplete = true
		case VerdictPass:
			hasPass = true
		}
	}

	switch {
	case hasFail:
		return verdictFailed
	case hasIncomplete:
		return verdictIncomplete
	case hasPass:
		return verdictPassed
	default:
		return verdictNotEvaluated
	}
}

func determineStatus(ra RequirementAssessment, threshold PassThreshold) RequirementStatus {
	if ra.EvaluatedControls == 0 {
		return RequirementNotEvaluated
	}

	if ra.IncompleteCount > 0 && ra.FailCount == 0 {
		return RequirementIncomplete
	}

	switch threshold.Mode {
	case ThresholdAll:
		if ra.FailCount == 0 && ra.IncompleteCount == 0 {
			return RequirementMet
		}
		return RequirementNotMet

	case ThresholdAny:
		if ra.PassCount >= 1 {
			return RequirementMet
		}
		return RequirementNotMet

	case ThresholdPercent:
		pct := float64(ra.PassCount) / float64(ra.EvaluatedControls) * 100
		if pct >= threshold.Percent {
			return RequirementMet
		}
		return RequirementNotMet

	default:
		return RequirementNotMet
	}
}
