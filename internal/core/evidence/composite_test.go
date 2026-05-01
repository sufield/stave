package evidence

import (
	"testing"
)

func TestBuildCompositeGaps_SharedGap(t *testing.T) {
	// One control failing across 3 frameworks.
	rec := &EvidenceRecord{
		ControlID:   "CTL.S3.ENCRYPT.001",
		ControlName: "S3 Encryption",
		ResourceARN: "arn:aws:s3:::phi-records",
		Verdict:     VerdictFail,
		Severity:    "high",
	}

	assessments := []*ProfileAssessment{
		{
			FrameworkID: "hipaa",
			Requirements: []RequirementAssessment{
				{RequirementID: "164.312(a)(2)(iv)", Description: "Encryption",
					Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec}},
			},
		},
		{
			FrameworkID: "fedramp_moderate",
			Requirements: []RequirementAssessment{
				{RequirementID: "SC-28", Description: "Protection at rest",
					Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec}},
			},
		},
		{
			FrameworkID: "soc2",
			Requirements: []RequirementAssessment{
				{RequirementID: "CC6.7", Description: "Encryption",
					Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec}},
			},
		},
	}

	report := BuildCompositeGaps(assessments)

	if len(report.SharedGaps) != 1 {
		t.Fatalf("SharedGaps = %d, want 1", len(report.SharedGaps))
	}

	gap := report.SharedGaps[0]
	if gap.FrameworkCount != 3 {
		t.Errorf("FrameworkCount = %d, want 3", gap.FrameworkCount)
	}
	if gap.ObligationsClosed != 3 {
		t.Errorf("ObligationsClosed = %d, want 3", gap.ObligationsClosed)
	}
	if gap.ControlID != "CTL.S3.ENCRYPT.001" {
		t.Errorf("ControlID = %q, want CTL.S3.ENCRYPT.001", gap.ControlID)
	}
	if len(report.UniqueGaps) != 0 {
		t.Errorf("UniqueGaps = %d, want 0", len(report.UniqueGaps))
	}
}

func TestBuildCompositeGaps_UniqueGap(t *testing.T) {
	rec := &EvidenceRecord{
		ControlID:   "CTL.IAM.MFA.001",
		ControlName: "IAM MFA",
		ResourceARN: "arn:aws:iam::123:user/legacy",
		Verdict:     VerdictFail,
		Severity:    "high",
	}

	assessments := []*ProfileAssessment{
		{
			FrameworkID: "hipaa",
			Requirements: []RequirementAssessment{
				{RequirementID: "164.312(a)(1)", Description: "Access control",
					Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec}},
			},
		},
	}

	report := BuildCompositeGaps(assessments)

	if len(report.SharedGaps) != 0 {
		t.Errorf("SharedGaps = %d, want 0 (only 1 framework)", len(report.SharedGaps))
	}
	if len(report.UniqueGaps) != 1 {
		t.Fatalf("UniqueGaps = %d, want 1", len(report.UniqueGaps))
	}
	if report.UniqueGaps[0].Framework != "hipaa" {
		t.Errorf("Framework = %q, want hipaa", report.UniqueGaps[0].Framework)
	}
}

func TestBuildCompositeGaps_TopNImpact(t *testing.T) {
	// 2 shared gaps: one closing 3 obligations, one closing 2.
	rec1 := &EvidenceRecord{ControlID: "CTL.A", ResourceARN: "arn:a", Verdict: VerdictFail, Severity: "high"}
	rec2 := &EvidenceRecord{ControlID: "CTL.B", ResourceARN: "arn:b", Verdict: VerdictFail, Severity: "medium"}

	assessments := []*ProfileAssessment{
		{FrameworkID: "hipaa", Requirements: []RequirementAssessment{
			{RequirementID: "H1", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec1}},
			{RequirementID: "H2", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec2}},
		}},
		{FrameworkID: "soc2", Requirements: []RequirementAssessment{
			{RequirementID: "S1", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec1}},
			{RequirementID: "S2", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec2}},
		}},
		{FrameworkID: "fedramp", Requirements: []RequirementAssessment{
			{RequirementID: "F1", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec1}},
		}},
	}

	report := BuildCompositeGaps(assessments)

	if len(report.SharedGaps) != 2 {
		t.Fatalf("SharedGaps = %d, want 2", len(report.SharedGaps))
	}

	// First gap (CTL.A) closes 3 obligations, second (CTL.B) closes 2.
	if report.SharedGaps[0].ObligationsClosed != 3 {
		t.Errorf("top gap obligations = %d, want 3", report.SharedGaps[0].ObligationsClosed)
	}
	if report.SharedGaps[1].ObligationsClosed != 2 {
		t.Errorf("second gap obligations = %d, want 2", report.SharedGaps[1].ObligationsClosed)
	}

	// Top-1 impact: 3 out of 5 total = 60%.
	if len(report.TopNSharedGapImpact) < 1 {
		t.Fatal("missing top-N impact")
	}
	top1 := report.TopNSharedGapImpact[0]
	if top1.ObligationsClosed != 3 {
		t.Errorf("top-1 obligations = %d, want 3", top1.ObligationsClosed)
	}
	if top1.TotalObligations != 5 {
		t.Errorf("total obligations = %d, want 5", top1.TotalObligations)
	}
	if top1.ClosurePercent != 60 {
		t.Errorf("top-1 closure = %.1f%%, want 60%%", top1.ClosurePercent)
	}
}

func TestBuildCompositeGaps_DeduplicatedViolations(t *testing.T) {
	// Same finding violates 2 requirements in the same framework.
	rec := &EvidenceRecord{ControlID: "CTL.X", ResourceARN: "arn:x", Verdict: VerdictFail, Severity: "high"}

	assessments := []*ProfileAssessment{
		{FrameworkID: "hipaa", Requirements: []RequirementAssessment{
			{RequirementID: "H1", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec}},
			{RequirementID: "H2", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec}},
		}},
		{FrameworkID: "soc2", Requirements: []RequirementAssessment{
			{RequirementID: "S1", Status: RequirementNotMet, Evidence: []*EvidenceRecord{rec}},
		}},
	}

	report := BuildCompositeGaps(assessments)

	if len(report.SharedGaps) != 1 {
		t.Fatalf("SharedGaps = %d, want 1", len(report.SharedGaps))
	}
	// Should have 3 violations (H1, H2, S1) but frameworks are hipaa + soc2.
	gap := report.SharedGaps[0]
	if gap.FrameworkCount != 2 {
		t.Errorf("FrameworkCount = %d, want 2", gap.FrameworkCount)
	}
	if gap.ObligationsClosed != 3 {
		t.Errorf("ObligationsClosed = %d, want 3 (H1 + H2 + S1)", gap.ObligationsClosed)
	}
}

func TestBuildCompositeGaps_PassingRecordsIgnored(t *testing.T) {
	pass := &EvidenceRecord{ControlID: "CTL.GOOD", ResourceARN: "arn:good", Verdict: VerdictPass, Severity: "high"}
	fail := &EvidenceRecord{ControlID: "CTL.BAD", ResourceARN: "arn:bad", Verdict: VerdictFail, Severity: "high"}

	assessments := []*ProfileAssessment{
		{FrameworkID: "hipaa", Requirements: []RequirementAssessment{
			{RequirementID: "H1", Status: RequirementMet, Evidence: []*EvidenceRecord{pass}},
			{RequirementID: "H2", Status: RequirementNotMet, Evidence: []*EvidenceRecord{fail}},
		}},
	}

	report := BuildCompositeGaps(assessments)

	// Only the failing record should appear.
	if report.UniqueGapCount != 1 {
		t.Errorf("UniqueGapCount = %d, want 1", report.UniqueGapCount)
	}
}
