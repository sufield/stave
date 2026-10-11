package compare

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func finding(ctl string, sev policy.Severity, fws map[policy.ComplianceFramework]string) remediation.Finding {
	mapping := make(policy.ComplianceMapping, len(fws))
	for k, v := range fws {
		mapping[k] = policy.RequirementID(v)
	}
	return remediation.Finding{
		ControlID:         kernel.ControlID(ctl),
		AssetID:           asset.ID("test-asset"),
		ControlSeverity:   sev,
		ControlCompliance: mapping,
	}
}

func TestAnalyze_SharedViolation(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", policy.SeverityHigh, map[policy.ComplianceFramework]string{
			"hipaa":            "164.312(b)",
			"fedramp_moderate": "AU-2",
		}),
	}

	r := Analyze(Input{
		BaselineName: "hipaa",
		TargetName:   "fedramp_moderate",
		BaselineKey:  "hipaa",
		TargetKey:    "fedramp_moderate",
		Findings:     findings,
	})

	if len(r.SharedViolations) != 1 {
		t.Fatalf("shared = %d, want 1", len(r.SharedViolations))
	}
	if r.SharedViolations[0].ControlID != "CTL.A.001" {
		t.Errorf("shared control = %q, want CTL.A.001", r.SharedViolations[0].ControlID)
	}
}

func TestAnalyze_TargetOnly(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", policy.SeverityHigh, map[policy.ComplianceFramework]string{
			"fedramp_moderate": "AU-2",
		}),
	}

	r := Analyze(Input{
		BaselineKey: "hipaa",
		TargetKey:   "fedramp_moderate",
		Findings:    findings,
	})

	if len(r.TargetOnly) != 1 {
		t.Fatalf("target-only = %d, want 1", len(r.TargetOnly))
	}
	if len(r.SharedViolations) != 0 {
		t.Errorf("shared = %d, want 0", len(r.SharedViolations))
	}
}

func TestAnalyze_ReadinessPercent(t *testing.T) {
	findings := []remediation.Finding{
		// Shared: in both
		finding("CTL.A.001", policy.SeverityHigh, map[policy.ComplianceFramework]string{
			"hipaa": "1", "soc2": "CC6",
		}),
		// Target-only: in soc2 only
		finding("CTL.B.001", policy.SeverityMedium, map[policy.ComplianceFramework]string{
			"soc2": "CC7",
		}),
	}

	r := Analyze(Input{
		BaselineKey: "hipaa",
		TargetKey:   "soc2",
		Findings:    findings,
	})

	// Target total = shared(1) + target-only(1) = 2.
	// Target-only violations = 1.
	// Readiness = (1 - 1/2) * 100 = 50%.
	if r.AdoptionReadiness.ReadinessPct != 50.0 {
		t.Errorf("readiness = %.1f, want 50.0", r.AdoptionReadiness.ReadinessPct)
	}
}

func TestAnalyze_SameProfile_AllShared(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", policy.SeverityHigh, map[policy.ComplianceFramework]string{
			"hipaa": "164.312",
		}),
		finding("CTL.B.001", policy.SeverityMedium, map[policy.ComplianceFramework]string{
			"hipaa": "164.308",
		}),
	}

	r := Analyze(Input{
		BaselineKey: "hipaa",
		TargetKey:   "hipaa",
		Findings:    findings,
	})

	if len(r.SharedViolations) != 2 {
		t.Errorf("shared = %d, want 2 (same framework)", len(r.SharedViolations))
	}
	if len(r.TargetOnly) != 0 {
		t.Errorf("target-only = %d, want 0", len(r.TargetOnly))
	}
}

func TestCompareItems_DomainMethods(t *testing.T) {
	items := CompareItems{
		{ControlID: kernel.ControlID("CTL.A.001"), Severity: policy.SeverityCritical},
		{ControlID: kernel.ControlID("CTL.B.002"), Severity: policy.SeverityHigh},
		{ControlID: kernel.ControlID("CTL.C.003"), Severity: policy.SeverityCritical},
	}

	if items.Len() != 3 {
		t.Errorf("Len() = %d, want 3", items.Len())
	}

	crit := items.BySeverity(policy.SeverityCritical)
	if crit.Len() != 2 {
		t.Errorf("BySeverity(Critical).Len() = %d, want 2", crit.Len())
	}

	high := items.BySeverity(policy.SeverityHigh)
	if high.Len() != 1 {
		t.Errorf("BySeverity(High).Len() = %d, want 1", high.Len())
	}

	var empty CompareItems
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.BySeverity(policy.SeverityCritical) != nil {
		t.Error("empty.BySeverity() should return nil")
	}
}

func TestRequirementIDs_DomainMethods(t *testing.T) {
	reqs := RequirementIDs{"AU-2", "164.312(b)"}
	if reqs.Len() != 2 {
		t.Errorf("Len() = %d, want 2", reqs.Len())
	}
	if !reqs.Contains("AU-2") {
		t.Error("Contains(AU-2) = false, want true")
	}
	if reqs.Contains("AC-1") {
		t.Error("Contains(AC-1) = true, want false")
	}
}

func TestControlIDs_DomainMethods(t *testing.T) {
	cids := ControlIDs{"CTL.A.001", "CTL.B.002"}
	if cids.Len() != 2 {
		t.Errorf("Len() = %d, want 2", cids.Len())
	}
	if !cids.Contains("CTL.A.001") {
		t.Error("Contains(CTL.A.001) = false, want true")
	}
	if cids.Contains("CTL.C.003") {
		t.Error("Contains(CTL.C.003) = true, want false")
	}
}

func TestDwellHours_DomainMethods(t *testing.T) {
	dh := DwellHours(48.0)
	if dh.Float64() != 48.0 {
		t.Errorf("Float64() = %v, want 48.0", dh.Float64())
	}
	if dh.Hours() != 48.0 {
		t.Errorf("Hours() = %v, want 48.0", dh.Hours())
	}
	if dh.Days() != 2.0 {
		t.Errorf("Days() = %v, want 2.0", dh.Days())
	}
	if dh.Duration() != 48*time.Hour {
		t.Errorf("Duration() = %v, want %v", dh.Duration(), 48*time.Hour)
	}
	if dh.IsZero() {
		t.Error("IsZero() = true for 48.0, want false")
	}
	if !DwellHours(0).IsZero() {
		t.Error("IsZero() = false for 0, want true")
	}
	if !dh.IsLongStanding(24.0) {
		t.Error("IsLongStanding(24.0) = false, want true")
	}
	if dh.IsLongStanding(72.0) {
		t.Error("IsLongStanding(72.0) = true, want false")
	}
}

func TestAdoptionPercentage_DomainMethods(t *testing.T) {
	ap := AdoptionPercentage(85.0)
	if ap.Float64() != 85.0 {
		t.Errorf("Float64() = %v, want 85.0", ap.Float64())
	}
	if ap.Ratio() != 0.85 {
		t.Errorf("Ratio() = %v, want 0.85", ap.Ratio())
	}
	if ap.IsComplete() {
		t.Error("IsComplete() = true for 85.0, want false")
	}
	if ap.Gap() != 15.0 {
		t.Errorf("Gap() = %v, want 15.0", ap.Gap())
	}
	if ap.IsAuditReady() {
		t.Error("IsAuditReady() = true for 85.0, want false")
	}

	full := AdoptionPercentage(100.0)
	if !full.IsComplete() {
		t.Error("IsComplete() = false for 100.0, want true")
	}
	if full.Gap() != 0.0 {
		t.Errorf("Gap() = %v, want 0.0", full.Gap())
	}
	if !full.IsAuditReady() {
		t.Error("IsAuditReady() = false for 100.0, want true")
	}
}

