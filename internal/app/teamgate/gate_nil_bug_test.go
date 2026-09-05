package teamgate

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestEvaluate_NilManifestHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Evaluate panicked on nil manifest: %v", rec)
		}
	}()

	in := Input{
		Findings: []remediation.Finding{
			{
				ControlID:       kernel.ControlID("CTL.S3.001"),
				ControlSeverity: policy.SeverityCritical,
				OwnerTeamID:     "team-alpha",
			},
		},
		Manifest:   nil, // nil manifest
		TeamID:     "team-alpha",
		Thresholds: DefaultThresholds(),
	}

	res := Evaluate(in)
	if res.TotalFindings != 1 {
		t.Errorf("expected 1 finding for team-alpha with nil manifest, got %d", res.TotalFindings)
	}
	if res.Passed {
		t.Errorf("expected gate failure for critical finding on team-alpha")
	}
}
