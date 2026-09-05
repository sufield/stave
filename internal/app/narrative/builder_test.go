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
