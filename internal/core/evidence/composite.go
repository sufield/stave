package evidence

import (
	"cmp"
	"slices"
)

// CompositeAssessment holds per-framework results and cross-framework
// gap analysis for multi-profile evaluation.
type CompositeAssessment struct {
	Frameworks    []string
	PerFramework  []*ProfileAssessment
	CompositeGaps CompositeGapReport
}

// CompositeGapReport analyzes gaps shared across multiple frameworks.
type CompositeGapReport struct {
	UniqueGapCount      int                `json:"unique_gap_count"`
	SharedGaps          []SharedGap        `json:"shared_gaps"`
	UniqueGaps          []UniqueGap        `json:"unique_gaps"`
	TopNSharedGapImpact []GapImpactSummary `json:"top_n_impact"`
}

// SharedGap is a finding that violates requirements in 2+ frameworks.
type SharedGap struct {
	ControlID          string               `json:"control_id"`
	ControlName        string               `json:"control_name"`
	ResourceARN        string               `json:"resource_arn"`
	Severity           string               `json:"severity"`
	FindingID          string               `json:"finding_id"`
	ViolatedFrameworks []FrameworkViolation `json:"violated_frameworks"`
	FrameworkCount     int                  `json:"framework_count"`
	ObligationsClosed  int                  `json:"obligations_closed"`
	RemediationAction  string               `json:"remediation_action,omitempty"`
}

// FrameworkViolation records which requirement in which framework a gap violates.
type FrameworkViolation struct {
	Framework       string `json:"framework"`
	RequirementID   string `json:"requirement_id"`
	RequirementDesc string `json:"requirement_description,omitempty"`
}

// UniqueGap is a finding that violates requirements in only one framework.
type UniqueGap struct {
	ControlID         string `json:"control_id"`
	ResourceARN       string `json:"resource_arn"`
	Severity          string `json:"severity"`
	FindingID         string `json:"finding_id"`
	Framework         string `json:"framework"`
	RequirementID     string `json:"requirement_id"`
	RemediationAction string `json:"remediation_action,omitempty"`
}

// GapImpactSummary shows what fixing the top-N shared gaps achieves.
type GapImpactSummary struct {
	TopNGaps          int     `json:"top_n_gaps"`
	ObligationsClosed int     `json:"obligations_closed"`
	TotalObligations  int     `json:"total_obligations"`
	ClosurePercent    float64 `json:"closure_percent"`
}

// BuildCompositeGaps analyzes gaps across multiple framework assessments.
// Each assessment is paired with its EvidencePackage for evidence access.
func BuildCompositeGaps(assessments []*ProfileAssessment, pkg *EvidencePackage) CompositeGapReport {
	type gapKey struct {
		controlID   string
		resourceARN string
	}
	type gapEntry struct {
		controlID   string
		controlName string
		resourceARN string
		severity    string
		findingID   string
		remediation string
		violations  []FrameworkViolation
	}

	gaps := make(map[gapKey]*gapEntry)

	// Collect all failing (control, resource) pairs across frameworks.
	for _, assessment := range assessments {
		for ri := range assessment.Requirements {
			req := &assessment.Requirements[ri]
			if req.Status == RequirementMet || req.Status == RequirementNotEvaluated {
				continue
			}
			for _, rec := range req.Evidence {
				if rec.Verdict != VerdictFail {
					continue
				}
				key := gapKey{controlID: rec.ControlID, resourceARN: rec.ResourceARN}
				entry, ok := gaps[key]
				if !ok {
					entry = &gapEntry{
						controlID:   rec.ControlID,
						controlName: rec.ControlName,
						resourceARN: rec.ResourceARN,
						severity:    rec.Severity,
						findingID:   findingIDFromRecord(rec),
					}
					if rec.ReasoningTrace.FindingMessage != "" {
						entry.remediation = rec.ReasoningTrace.FindingMessage
					}
					gaps[key] = entry
				}
				entry.violations = append(entry.violations, FrameworkViolation{
					Framework:       assessment.FrameworkID,
					RequirementID:   req.RequirementID,
					RequirementDesc: req.Description,
				})
			}
		}
	}

	// Partition into shared and unique.
	var shared []SharedGap
	var unique []UniqueGap
	uniqueControlIDs := make(map[string]bool)

	for _, entry := range gaps {
		uniqueControlIDs[entry.controlID] = true
		fwSet := make(map[string]bool)
		for _, v := range entry.violations {
			fwSet[v.Framework] = true
		}

		if len(fwSet) >= 2 {
			shared = append(shared, SharedGap{
				ControlID:          entry.controlID,
				ControlName:        entry.controlName,
				ResourceARN:        entry.resourceARN,
				Severity:           entry.severity,
				FindingID:          entry.findingID,
				ViolatedFrameworks: deduplicateViolations(entry.violations),
				FrameworkCount:     len(fwSet),
				ObligationsClosed:  len(entry.violations),
				RemediationAction:  entry.remediation,
			})
		} else {
			for _, v := range entry.violations {
				unique = append(unique, UniqueGap{
					ControlID:         entry.controlID,
					ResourceARN:       entry.resourceARN,
					Severity:          entry.severity,
					FindingID:         entry.findingID,
					Framework:         v.Framework,
					RequirementID:     v.RequirementID,
					RemediationAction: entry.remediation,
				})
			}
		}
	}

	// Sort shared by obligations_closed descending.
	slices.SortFunc(shared, func(a, b SharedGap) int {
		return cmp.Or(
			cmp.Compare(b.ObligationsClosed, a.ObligationsClosed),
			cmp.Compare(a.ControlID, b.ControlID),
		)
	})

	// Sort unique by framework then control.
	slices.SortFunc(unique, func(a, b UniqueGap) int {
		return cmp.Or(
			cmp.Compare(a.Framework, b.Framework),
			cmp.Compare(a.ControlID, b.ControlID),
		)
	})

	// Compute total obligations.
	totalObligations := 0
	for i := range shared {
		totalObligations += shared[i].ObligationsClosed
	}
	totalObligations += len(unique)

	// Top-N impact.
	var topN []GapImpactSummary
	for _, n := range []int{1, 5, 10, 20} {
		if n > len(shared) {
			n = len(shared)
		}
		closed := 0
		for i := range n {
			closed += shared[i].ObligationsClosed
		}
		pct := 0.0
		if totalObligations > 0 {
			pct = float64(closed) / float64(totalObligations) * 100
		}
		topN = append(topN, GapImpactSummary{
			TopNGaps:          n,
			ObligationsClosed: closed,
			TotalObligations:  totalObligations,
			ClosurePercent:    pct,
		})
	}

	return CompositeGapReport{
		UniqueGapCount:      len(uniqueControlIDs),
		SharedGaps:          shared,
		UniqueGaps:          unique,
		TopNSharedGapImpact: topN,
	}
}

func findingIDFromRecord(rec *EvidenceRecord) string {
	// EvidenceRecord doesn't have FindingID directly — derive from
	// control + resource as a stable key.
	return rec.ControlID + "@" + rec.ResourceARN
}

func deduplicateViolations(vs []FrameworkViolation) []FrameworkViolation {
	seen := make(map[string]bool)
	var out []FrameworkViolation
	for _, v := range vs {
		key := v.Framework + ":" + v.RequirementID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out
}
