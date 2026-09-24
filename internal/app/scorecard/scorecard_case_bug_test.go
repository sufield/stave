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
