package evidence

import (
	"testing"
	"time"
)

func testProfile(reqs ...Requirement) *FrameworkProfile {
	return &FrameworkProfile{
		ID:           "test",
		Name:         "Test Framework",
		Version:      "1.0",
		FrameworkKey: "test",
		Requirements: reqs,
	}
}

func testPkg(records ...*EvidenceRecord) *EvidencePackage {
	pkg := NewEvidencePackage("snap-001", time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))
	for _, r := range records {
		pkg.Add(r)
	}
	return pkg
}

func rec(controlID, resource string, verdict EvidenceVerdict) *EvidenceRecord {
	return &EvidenceRecord{
		ControlID:   controlID,
		ResourceARN: resource,
		Verdict:     verdict,
	}
}

func TestEvaluateProfile_AllPass_ThresholdAll(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictPass),
		rec("CTL.B", "arn:1", VerdictPass),
	)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A", "CTL.B"},
		PassThreshold: PassThreshold{Mode: ThresholdAll},
	})

	result := EvaluateProfile(pkg, profile)

	if len(result.Requirements) != 1 {
		t.Fatalf("len(Requirements) = %d", len(result.Requirements))
	}
	r := result.Requirements[0]
	if r.Status != RequirementMet {
		t.Errorf("Status = %v, want RequirementMet", r.Status)
	}
	if r.PassCount != 2 || r.FailCount != 0 {
		t.Errorf("PassCount=%d FailCount=%d", r.PassCount, r.FailCount)
	}
	if result.MetCount != 1 {
		t.Errorf("MetCount = %d", result.MetCount)
	}
}

func TestEvaluateProfile_OneFail_ThresholdAll(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictPass),
		rec("CTL.B", "arn:1", VerdictFail),
	)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A", "CTL.B"},
		PassThreshold: PassThreshold{Mode: ThresholdAll},
	})

	result := EvaluateProfile(pkg, profile)

	r := result.Requirements[0]
	if r.Status != RequirementNotMet {
		t.Errorf("Status = %v, want RequirementNotMet", r.Status)
	}
	if result.NotMetCount != 1 {
		t.Errorf("NotMetCount = %d", result.NotMetCount)
	}
}

func TestEvaluateProfile_ThresholdAny_OnePassAmongFails(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictFail),
		rec("CTL.B", "arn:1", VerdictPass),
		rec("CTL.C", "arn:1", VerdictFail),
	)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A", "CTL.B", "CTL.C"},
		PassThreshold: PassThreshold{Mode: ThresholdAny},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementMet {
		t.Errorf("Status = %v, want RequirementMet (threshold any)", r.Status)
	}
}

func TestEvaluateProfile_PercentMet(t *testing.T) {
	// 9 pass, 1 fail = 90% — threshold percent:80 should be met
	var records []*EvidenceRecord
	var ids []string
	for i := range 10 {
		id := "CTL." + string(rune('A'+i))
		ids = append(ids, id)
		v := VerdictPass
		if i == 9 {
			v = VerdictFail
		}
		records = append(records, rec(id, "arn:1", v))
	}
	pkg := testPkg(records...)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    ids,
		PassThreshold: PassThreshold{Mode: ThresholdPercent, Percent: 80},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementMet {
		t.Errorf("Status = %v, want RequirementMet (90%% >= 80%%)", r.Status)
	}
}

func TestEvaluateProfile_PercentNotMet(t *testing.T) {
	// 7 pass, 3 fail = 70% — threshold percent:80 should not be met
	var records []*EvidenceRecord
	var ids []string
	for i := range 10 {
		id := "CTL." + string(rune('A'+i))
		ids = append(ids, id)
		v := VerdictPass
		if i >= 7 {
			v = VerdictFail
		}
		records = append(records, rec(id, "arn:1", v))
	}
	pkg := testPkg(records...)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    ids,
		PassThreshold: PassThreshold{Mode: ThresholdPercent, Percent: 80},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementNotMet {
		t.Errorf("Status = %v, want RequirementNotMet (70%% < 80%%)", r.Status)
	}
}

func TestEvaluateProfile_NoEvidence(t *testing.T) {
	pkg := testPkg() // empty
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A", "CTL.B"},
		PassThreshold: PassThreshold{Mode: ThresholdAll},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementNotEvaluated {
		t.Errorf("Status = %v, want RequirementNotEvaluated", r.Status)
	}
}

func TestEvaluateProfile_IncompleteEvidence(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictPass),
		rec("CTL.B", "arn:1", VerdictIncomplete),
	)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A", "CTL.B"},
		PassThreshold: PassThreshold{Mode: ThresholdAll},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementIncomplete {
		t.Errorf("Status = %v, want RequirementIncomplete", r.Status)
	}
}

func TestEvaluateProfile_MixedRequirements(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictPass),
		rec("CTL.B", "arn:1", VerdictFail),
	)
	profile := testProfile(
		Requirement{ID: "R1", ControlIDs: []string{"CTL.A"}, PassThreshold: PassThreshold{Mode: ThresholdAll}},
		Requirement{ID: "R2", ControlIDs: []string{"CTL.B"}, PassThreshold: PassThreshold{Mode: ThresholdAll}},
		Requirement{ID: "R3", ControlIDs: []string{"CTL.MISSING"}, PassThreshold: PassThreshold{Mode: ThresholdAll}},
	)

	result := EvaluateProfile(pkg, profile)
	if result.MetCount != 1 {
		t.Errorf("MetCount = %d, want 1", result.MetCount)
	}
	if result.NotMetCount != 1 {
		t.Errorf("NotMetCount = %d, want 1", result.NotMetCount)
	}
	if result.NotEvaluatedCount != 1 {
		t.Errorf("NotEvaluatedCount = %d, want 1", result.NotEvaluatedCount)
	}
	if result.TotalRequirements != 3 {
		t.Errorf("TotalRequirements = %d, want 3", result.TotalRequirements)
	}
}

func TestEvaluateProfile_CoveragePercent(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictPass),
		rec("CTL.B", "arn:1", VerdictFail),
	)
	profile := testProfile(
		Requirement{ID: "R1", ControlIDs: []string{"CTL.A"}, PassThreshold: PassThreshold{Mode: ThresholdAll}},
		Requirement{ID: "R2", ControlIDs: []string{"CTL.B"}, PassThreshold: PassThreshold{Mode: ThresholdAll}},
	)

	result := EvaluateProfile(pkg, profile)
	// 1 met / 2 total = 50%
	if result.CoveragePercent != 50 {
		t.Errorf("CoveragePercent = %v, want 50", result.CoveragePercent)
	}
}

func TestEvaluateProfile_MultipleResources_WorstVerdictWins(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictPass),
		rec("CTL.A", "arn:2", VerdictPass),
		rec("CTL.A", "arn:3", VerdictFail), // one fail makes the control fail
	)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A"},
		PassThreshold: PassThreshold{Mode: ThresholdAll},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementNotMet {
		t.Errorf("Status = %v, want RequirementNotMet (worst verdict wins)", r.Status)
	}
	if r.FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", r.FailCount)
	}
}

func TestEvaluateProfile_AllNotApplicable(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictNotApplicable),
		rec("CTL.A", "arn:2", VerdictNotApplicable),
	)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A"},
		PassThreshold: PassThreshold{Mode: ThresholdAll},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementNotEvaluated {
		t.Errorf("Status = %v, want RequirementNotEvaluated (all N/A)", r.Status)
	}
}

func TestEvaluateProfile_EmptyPackage(t *testing.T) {
	pkg := testPkg()
	profile := testProfile(
		Requirement{ID: "R1", ControlIDs: []string{"CTL.A"}},
		Requirement{ID: "R2", ControlIDs: []string{"CTL.B"}},
	)

	result := EvaluateProfile(pkg, profile)
	if result.NotEvaluatedCount != 2 {
		t.Errorf("NotEvaluatedCount = %d, want 2", result.NotEvaluatedCount)
	}
}

func TestEvaluateProfile_EmptyProfile(t *testing.T) {
	pkg := testPkg(rec("CTL.A", "arn:1", VerdictPass))
	profile := testProfile() // no requirements

	result := EvaluateProfile(pkg, profile)
	if result.TotalRequirements != 0 {
		t.Errorf("TotalRequirements = %d, want 0", result.TotalRequirements)
	}
	if len(result.Requirements) != 0 {
		t.Errorf("len(Requirements) = %d", len(result.Requirements))
	}
}

func TestEvaluateProfile_SingleControl_PassAndFail_Fails(t *testing.T) {
	// Same control, different resources: one pass one fail → control fails
	pkg := testPkg(
		rec("CTL.A", "arn:1", VerdictPass),
		rec("CTL.A", "arn:2", VerdictFail),
	)
	profile := testProfile(Requirement{
		ID:            "R1",
		ControlIDs:    []string{"CTL.A"},
		PassThreshold: PassThreshold{Mode: ThresholdAll},
	})

	r := EvaluateProfile(pkg, profile).Requirements[0]
	if r.Status != RequirementNotMet {
		t.Errorf("Status = %v, want RequirementNotMet", r.Status)
	}
}
