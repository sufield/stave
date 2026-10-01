package scorecard

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestCompute_CaseInsensitiveFrameworkMatching(t *testing.T) {
	findings := []remediation.Finding{
		{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			ControlSeverity: policy.SeverityHigh,
			ControlCompliance: policy.ComplianceMapping{
				"nist-800-53": "AC-2",
			},
		},
	}

	// Request scorecard for uppercase framework name
	rep := Compute(findings, []policy.ComplianceFramework{"NIST-800-53"})
	if len(rep.Frameworks) != 1 {
		t.Fatalf("expected 1 framework score, got %d", len(rep.Frameworks))
	}

	if rep.Frameworks[0].ControlsTotal != 1 {
		t.Errorf("expected 1 control matching NIST-800-53, got %d", rep.Frameworks[0].ControlsTotal)
	}
}

func TestComplianceFrameworks_DomainMethods(t *testing.T) {
	cfs := ComplianceFrameworks{"HIPAA", "NIST-800-53"}

	if cfs.Len() != 2 {
		t.Errorf("Len: got %d, want 2", cfs.Len())
	}
	if !cfs.Contains("HIPAA") {
		t.Error("Contains HIPAA: got false, want true")
	}
	if cfs.Contains("SOC2") {
		t.Error("Contains SOC2: got true, want false")
	}
}

func TestReadinessPercentage_DomainMethods(t *testing.T) {
	rp := ReadinessPercentage(95.5)

	if rp.Value() != 95.5 {
		t.Errorf("Value() = %f, want 95.5", rp.Value())
	}
	if !rp.IsAuditReady() {
		t.Errorf("IsAuditReady() = false, want true for 95.5")
	}
	if ReadinessPercentage(85.0).IsAuditReady() {
		t.Errorf("IsAuditReady() = true, want false for 85.0")
	}
	if gap := rp.Gap(); gap != 4.5 {
		t.Errorf("Gap() = %f, want 4.5", gap)
	}
	if gap := ReadinessPercentage(100.0).Gap(); gap != 0.0 {
		t.Errorf("Gap() for 100%% = %f, want 0.0", gap)
	}
	if clamped := ReadinessPercentage(-10.0).Clamp(); clamped != 0.0 {
		t.Errorf("Clamp(-10) = %f, want 0.0", clamped)
	}
	if clamped := ReadinessPercentage(150.0).Clamp(); clamped != 100.0 {
		t.Errorf("Clamp(150) = %f, want 100.0", clamped)
	}
}
