package evidence

// EvaluateProfile evaluates an EvidencePackage against a FrameworkProfile,
// producing a ProfileAssessment with per-requirement coverage scores.
// It is a pure function with no side effects.
//
// Nil-input contract:
//   - profile == nil: returns a zero-value *ProfileAssessment. The
//     framework metadata fields cannot be populated without a
//     profile, and panicking here would mask the wiring bug behind
//     a stack trace far from the call site. Returning the zero
//     value lets the caller render an empty assessment that
//     surfaces "no framework configured" downstream.
//   - pkg == nil: every requirement evaluates to NotEvaluated (no
//     records to score against), which is the correct outcome —
//     evaluateRequirement handles the nil-pkg case below.
func EvaluateProfile(pkg *EvidencePackage, profile *FrameworkProfile) *ProfileAssessment {
	if profile == nil {
		return &ProfileAssessment{}
	}
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

// evaluateRequirement scores a single requirement against the
// evidence package. A nil pkg short-circuits to a NotEvaluated
// status: there are no records to look up, so every control under
// this requirement reads as "no signal". Mirrors the EvaluateProfile
// nil-input contract.
func evaluateRequirement(pkg *EvidencePackage, req *Requirement) RequirementAssessment {
	ra := RequirementAssessment{
		RequirementID: req.ID,
		Description:   req.Description,
		Section:       req.Section,
		TotalControls: len(req.ControlIDs),
	}

	if pkg == nil {
		ra.Status = RequirementNotEvaluated
		return ra
	}

	for _, controlID := range req.ControlIDs {
		records := pkg.FindByControlID(controlID)
		if len(records) == 0 {
			continue
		}

		verdict := aggregateControlVerdict(records)
		if verdict == VerdictNotApplicable {
			// All records were NotApplicable — treat as not evaluated.
			continue
		}

		ra.EvaluatedControls++
		ra.Evidence = append(ra.Evidence, records...)

		switch verdict {
		case VerdictPass:
			ra.PassCount++
		case VerdictFail:
			ra.FailCount++
		case VerdictIncomplete:
			ra.IncompleteCount++
		}
	}

	ra.Status = determineStatus(ra, req.PassThreshold)

	if ra.EvaluatedControls > 0 {
		ra.CoveragePercent = float64(ra.PassCount) / float64(ra.EvaluatedControls) * 100
	}

	return ra
}

// aggregateControlVerdict determines the worst-case verdict for a
// control across all its evidence records. Delegates to the same
// counts-based precedence rule (aggregateFromCounts) used by
// EvidencePackage.AggregateVerdict so the rule lives in one place.
// Returns the typed EvidenceVerdict directly — VerdictNotApplicable
// signals "no decisive record" so callers can skip the requirement.
func aggregateControlVerdict(records []*EvidenceRecord) EvidenceVerdict {
	var pass, fail, incomplete int
	for _, r := range records {
		switch {
		case r.IsFail():
			fail++
		case r.IsIncomplete():
			incomplete++
		case r.IsPass():
			pass++
		}
	}
	return aggregateFromCounts(pass, fail, incomplete)
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
