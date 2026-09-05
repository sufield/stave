package compare

import (
	"testing"

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
