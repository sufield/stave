package compliance

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evidence"
)

var testTime = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

func testPkg(records ...*evidence.EvidenceRecord) *evidence.EvidencePackage {
	pkg := evidence.NewEvidencePackage("snap-001", testTime)
	for _, r := range records {
		pkg.Add(r)
	}
	return pkg
}

func rec(controlID, resource string, verdict evidence.EvidenceVerdict, severity string) *evidence.EvidenceRecord {
	return &evidence.EvidenceRecord{
		ControlID:   controlID,
		ControlName: controlID + " name",
		ResourceARN: resource,
		Verdict:     verdict,
		Severity:    severity,
		Citations:   []evidence.Citation{{Framework: "test", Requirement: "R1"}},
		ReasoningTrace: evidence.ReasoningTrace{
			FindingMessage: controlID + " finding",
		},
	}
}

func TestBuildExport_BasicStructure(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", evidence.VerdictFail, "critical"),
		rec("CTL.B", "arn:2", evidence.VerdictPass, "high"),
	)
	profile := &evidence.FrameworkProfile{
		ID: "test", Name: "Test", Version: "1.0",
		Requirements: []evidence.Requirement{{
			ID:            "R1",
			ControlIDs:    []string{"CTL.A", "CTL.B"},
			PassThreshold: evidence.PassThreshold{Mode: evidence.ThresholdAll},
		}},
	}
	assessment := evidence.EvaluateProfile(pkg, profile)

	export := buildExport(profile, assessment, pkg, "dev", testTime, false, "all", nil)

	if export.Profile.ID != "test" {
		t.Errorf("Profile.ID = %q", export.Profile.ID)
	}
	if export.StaveVersion != "dev" {
		t.Errorf("StaveVersion = %q", export.StaveVersion)
	}
	if export.Score.RequirementsTotal != 1 {
		t.Errorf("RequirementsTotal = %d", export.Score.RequirementsTotal)
	}
	if len(export.Requirements) != 1 {
		t.Fatalf("len(Requirements) = %d", len(export.Requirements))
	}
	if export.Requirements[0].Status != "not_met" {
		t.Errorf("Status = %q", export.Requirements[0].Status)
	}
}

func TestBuildExport_IncludePassFalse(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", evidence.VerdictFail, "critical"),
		rec("CTL.B", "arn:2", evidence.VerdictPass, "high"),
	)
	profile := &evidence.FrameworkProfile{
		ID: "test", Name: "Test", Version: "1.0",
	}
	assessment := evidence.EvaluateProfile(pkg, profile)

	export := buildExport(profile, assessment, pkg, "dev", testTime, false, "all", nil)

	// Only fail records included (pass excluded)
	if len(export.Evidence) != 1 {
		t.Fatalf("len(Evidence) = %d, want 1 (pass excluded)", len(export.Evidence))
	}
	if export.Evidence[0].Verdict != "fail" {
		t.Errorf("Verdict = %q, want fail", export.Evidence[0].Verdict)
	}
}

func TestBuildExport_IncludePassTrue(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", evidence.VerdictFail, "critical"),
		rec("CTL.B", "arn:2", evidence.VerdictPass, "high"),
	)
	profile := &evidence.FrameworkProfile{
		ID: "test", Name: "Test", Version: "1.0",
	}
	assessment := evidence.EvaluateProfile(pkg, profile)

	export := buildExport(profile, assessment, pkg, "dev", testTime, true, "all", nil)

	if len(export.Evidence) != 2 {
		t.Fatalf("len(Evidence) = %d, want 2 (pass included)", len(export.Evidence))
	}
}

func TestBuildExport_MinSeverityFilter(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", evidence.VerdictFail, "critical"),
		rec("CTL.B", "arn:2", evidence.VerdictFail, "low"),
		rec("CTL.C", "arn:3", evidence.VerdictFail, "high"),
	)
	profile := &evidence.FrameworkProfile{
		ID: "test", Name: "Test", Version: "1.0",
	}
	assessment := evidence.EvaluateProfile(pkg, profile)

	export := buildExport(profile, assessment, pkg, "dev", testTime, false, "high", nil)

	// Only critical and high (not low)
	if len(export.Evidence) != 2 {
		t.Fatalf("len(Evidence) = %d, want 2 (critical+high)", len(export.Evidence))
	}
}

func TestBuildExport_GapsPopulated(t *testing.T) {
	pkg := testPkg(
		rec("CTL.A", "arn:1", evidence.VerdictFail, "critical"),
		rec("CTL.A", "arn:2", evidence.VerdictPass, "critical"),
	)
	profile := &evidence.FrameworkProfile{
		ID: "test", Name: "Test", Version: "1.0",
		Requirements: []evidence.Requirement{{
			ID:            "R1",
			ControlIDs:    []string{"CTL.A"},
			PassThreshold: evidence.PassThreshold{Mode: evidence.ThresholdAll},
		}},
	}
	assessment := evidence.EvaluateProfile(pkg, profile)

	export := buildExport(profile, assessment, pkg, "dev", testTime, false, "all", nil)

	if len(export.Requirements[0].Gaps) != 1 {
		t.Fatalf("len(Gaps) = %d, want 1", len(export.Requirements[0].Gaps))
	}
	gap := export.Requirements[0].Gaps[0]
	if gap.ControlID != "CTL.A" || gap.ResourceARN != "arn:1" {
		t.Errorf("Gap = %+v", gap)
	}
}

func TestMatchesSeverity(t *testing.T) {
	tests := []struct {
		record, min string
		want        bool
	}{
		{"critical", "all", true},
		{"low", "all", true},
		{"critical", "high", true},
		{"high", "high", true},
		{"medium", "high", false},
		{"low", "critical", false},
		{"critical", "", true},
	}
	for _, tt := range tests {
		if got := matchesSeverity(tt.record, tt.min); got != tt.want {
			t.Errorf("matchesSeverity(%q, %q) = %v, want %v", tt.record, tt.min, got, tt.want)
		}
	}
}
