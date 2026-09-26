package narrative

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuildSteps_SafeDefaultFirst(t *testing.T) {
	spec := policy.RemediationSpec{
		Changes: []policy.PropertyChange{
			{PropertyPath: "dangerous.setting", HasSafeDefault: false, CurrentValue: "x", RequiredValue: "y"},
			{PropertyPath: "safe.setting", HasSafeDefault: true, CurrentValue: "a", RequiredValue: "b"},
		},
	}
	steps := buildSteps(spec)
	if len(steps) < 2 {
		t.Fatalf("steps = %d, want >= 2", len(steps))
	}
	// Safe-default should be step 1.
	if !steps[0].SafeDefault {
		t.Error("step 1 should be safe-default")
	}
}

func TestBuildSteps_CautionOnUnsafe(t *testing.T) {
	spec := policy.RemediationSpec{
		Changes: []policy.PropertyChange{
			{PropertyPath: "risky.setting", HasSafeDefault: false, CurrentValue: "old", RequiredValue: "new"},
		},
	}
	steps := buildSteps(spec)
	if len(steps) == 0 {
		t.Fatal("expected at least 1 step")
	}
	if steps[0].Caution == "" {
		t.Error("expected caution for non-safe-default change")
	}
}

func TestBuildPlaybook_NoChainContext(t *testing.T) {
	f := remediation.Finding{
		ControlID:       "CTL.TEST.001",
		ControlName:     "Test Control",
		AssetID:         "res-1",
		ControlSeverity: policy.SeverityHigh,
		RemediationSpec: policy.RemediationSpec{
			Action: "Fix it",
		},
	}
	pb := BuildPlaybook(&Input{Finding: f})
	if pb.Narrative.ChainContext != nil {
		t.Error("expected nil chain context when no chain membership")
	}
}

func TestBuildPlaybook_WhyOmitsReachabilityWhenAbsent(t *testing.T) {
	f := remediation.Finding{
		ControlID:          "CTL.TEST.001",
		ControlName:        "Test",
		ControlDescription: "Test description",
		AssetID:            "res-1",
		RemediationSpec:    policy.RemediationSpec{Action: "fix"},
	}
	pb := BuildPlaybook(&Input{Finding: f})
	if pb.Narrative.WhyThisMatters == "" {
		t.Error("expected why section from description")
	}
	// Should NOT contain "Reachability" since finding has no reachability.
	if contains(pb.Narrative.WhyThisMatters, "Reachability") {
		t.Error("why section should not mention reachability when absent")
	}
}

func TestChainDeactivationOrder(t *testing.T) {
	ids := []kernel.ControlID{
		"CTL.S3.PUBLIC.001",          // exposure → last
		"CTL.KMS.ROTATION.001",       // crypto → second
		"CTL.CLOUDTRAIL.ENABLED.001", // detection → first
	}
	order := chainDeactivationOrder(ids)
	if len(order) != 3 {
		t.Fatalf("order = %d, want 3", len(order))
	}
	// Detection (TRAIL) should be first.
	if order[0] != "CTL.CLOUDTRAIL.ENABLED.001" {
		t.Errorf("first = %q, want CTL.CLOUDTRAIL.ENABLED.001", order[0])
	}
	// Crypto (KMS) should be second.
	if order[1] != "CTL.KMS.ROTATION.001" {
		t.Errorf("second = %q, want CTL.KMS.ROTATION.001", order[1])
	}
	// Exposure (S3) should be last.
	if order[2] != "CTL.S3.PUBLIC.001" {
		t.Errorf("third = %q, want CTL.S3.PUBLIC.001", order[2])
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSteps_CollectionMethods(t *testing.T) {
	steps := Steps{
		{StepNumber: 1, SafeDefault: true, Caution: ""},
		{StepNumber: 2, SafeDefault: false, Caution: "High impact"},
	}

	if steps.Len() != 2 {
		t.Errorf("steps.Len() = %d, want 2", steps.Len())
	}

	if steps.SafeDefaults().Len() != 1 {
		t.Errorf("SafeDefaults len = %d, want 1", steps.SafeDefaults().Len())
	}

	if steps.RequiresCaution().Len() != 1 {
		t.Errorf("RequiresCaution len = %d, want 1", steps.RequiresCaution().Len())
	}
}

func TestChainMembers_CollectionMethods(t *testing.T) {
	members := ChainMembers{
		{ControlID: "CTL.A.001", Status: StatusPassing},
		{ControlID: "CTL.B.002", Status: StatusThisFinding},
		{ControlID: "CTL.C.003", Status: StatusAlsoFailing},
	}

	if members.Len() != 3 {
		t.Errorf("members.Len() = %d, want 3", members.Len())
	}

	if members.Passing().Len() != 1 {
		t.Errorf("Passing() len = %d, want 1", members.Passing().Len())
	}

	if members.Failing().Len() != 2 {
		t.Errorf("Failing() len = %d, want 2", members.Failing().Len())
	}

	m := members.ByControl("CTL.A.001")
	if m == nil || !m.IsPassing() {
		t.Errorf("ByControl(CTL.A.001) failed")
	}

	if members.ByControl("CTL.NONEXISTENT") != nil {
		t.Errorf("ByControl(nonexistent) expected nil")
	}

	var empty ChainMembers
	if empty.Len() != 0 || empty.Passing() != nil || empty.Failing() != nil || empty.ByControl("CTL.A.001") != nil {
		t.Errorf("empty ChainMembers methods failed")
	}
}

func TestStateEntries_DomainMethods(t *testing.T) {
	entries := StateEntries{
		{PropertyPath: "s3.public", CurrentValue: "true", RequiredValue: "false"},
		{PropertyPath: "s3.ssl", CurrentValue: "false", RequiredValue: "true"},
	}

	if entries.Len() != 2 {
		t.Errorf("entries.Len() = %d, want 2", entries.Len())
	}

	pub := entries.ByPropertyPath("s3.public")
	if pub == nil || pub.CurrentValue != "true" {
		t.Errorf("ByPropertyPath(s3.public) = %v, want true", pub)
	}

	missing := entries.ByPropertyPath("s3.encryption")
	if missing != nil {
		t.Errorf("ByPropertyPath(s3.encryption) = %v, want nil", missing)
	}

	var empty StateEntries
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.ByPropertyPath("s3.public") != nil {
		t.Error("empty.ByPropertyPath() should return nil")
	}
}
