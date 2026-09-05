package compare

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Compare_DwellHoursDeterministic(t *testing.T) {
	// Two findings for the same control with different dwell hours
	f1 := remediation.Finding{
		ControlID:         kernel.ControlID("CTL.A.001"),
		AssetID:           asset.ID("asset-1"),
		ControlSeverity:   policy.SeverityHigh,
		ControlCompliance: policy.ComplianceMapping{"hipaa": "164.312"},
		Evidence: evaluation.Evidence{
			UnsafeDurationHours: 10.0,
		},
	}

	f2 := remediation.Finding{
		ControlID:         kernel.ControlID("CTL.A.001"),
		AssetID:           asset.ID("asset-2"),
		ControlSeverity:   policy.SeverityHigh,
		ControlCompliance: policy.ComplianceMapping{"hipaa": "164.312"},
		Evidence: evaluation.Evidence{
			UnsafeDurationHours: 50.0,
		},
	}

	// Run with f1 first (should deterministically pick max/worst-case dwell hours: 50.0)
	r1 := Analyze(Input{
		BaselineKey: "hipaa",
		TargetKey:   "hipaa",
		Findings:    []remediation.Finding{f1, f2},
	})

	if len(r1.SharedViolations) != 1 {
		t.Fatalf("expected 1 shared violation, got %d", len(r1.SharedViolations))
	}

	if r1.SharedViolations[0].DwellHours != 50.0 {
		t.Errorf("List [f1, f2]: expected DwellHours = 50.0, got %f", r1.SharedViolations[0].DwellHours)
	}

	// Run with f2 first
	r2 := Analyze(Input{
		BaselineKey: "hipaa",
		TargetKey:   "hipaa",
		Findings:    []remediation.Finding{f2, f1},
	})

	if len(r2.SharedViolations) != 1 {
		t.Fatalf("expected 1 shared violation, got %d", len(r2.SharedViolations))
	}

	if r2.SharedViolations[0].DwellHours != 50.0 {
		t.Errorf("List [f2, f1]: expected DwellHours = 50.0, got %f", r2.SharedViolations[0].DwellHours)
	}
}
