package stave

import (
	"context"
	"strings"
	"testing"
)

// demoObs is a bundled fixture with several mapped, failing controls —
// good for exercising compliance projection.
const demoObs = "../../examples/demo-s3-public-read/fixtures/observations"

// TestComplianceMulti_MatchesPerFramework proves the single-pass
// evaluator returns the same per-framework posture as calling
// Compliance once per framework, and preserves the requested order.
func TestComplianceMulti_MatchesPerFramework(t *testing.T) {
	ctx := context.Background()
	fws := []string{"pci_dss_v4.0", "cis_aws_v3.0"}

	multi, err := ComplianceMulti(ctx, demoObs, fws)
	if err != nil {
		t.Fatalf("ComplianceMulti: %v", err)
	}
	if len(multi) != len(fws) {
		t.Fatalf("got %d reports, want %d", len(multi), len(fws))
	}

	for i, fw := range fws {
		if multi[i].FrameworkID != fw {
			t.Errorf("report[%d].FrameworkID = %q, want %q (order not preserved)", i, multi[i].FrameworkID, fw)
		}
		single, err := Compliance(ctx, demoObs, fw)
		if err != nil {
			t.Fatalf("Compliance(%s): %v", fw, err)
		}
		if multi[i].TotalRequirements != single.TotalRequirements ||
			multi[i].MetCount != single.MetCount ||
			multi[i].NotMetCount != single.NotMetCount {
			t.Errorf("framework %s: single-pass differs from per-framework (multi %d/%d met=%d, single %d/%d met=%d)",
				fw, multi[i].MetCount, multi[i].TotalRequirements, multi[i].NotMetCount,
				single.MetCount, single.TotalRequirements, single.NotMetCount)
		}
	}
}

// TestComplianceMulti_DefaultsToAllFrameworks confirms an empty list
// evaluates every available framework.
func TestComplianceMulti_DefaultsToAllFrameworks(t *testing.T) {
	reports, err := ComplianceMulti(context.Background(), demoObs, nil)
	if err != nil {
		t.Fatalf("ComplianceMulti(nil): %v", err)
	}
	if len(reports) != len(AvailableFrameworks()) {
		t.Errorf("default got %d reports, want %d (all frameworks)", len(reports), len(AvailableFrameworks()))
	}
}

// TestComplianceMulti_UnknownFramework confirms an unknown framework
// fails loudly with the available list.
func TestComplianceMulti_UnknownFramework(t *testing.T) {
	_, err := ComplianceMulti(context.Background(), demoObs, []string{"hipaa", "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
	if !strings.Contains(err.Error(), "available:") {
		t.Errorf("error should list available profiles, got: %v", err)
	}
}
