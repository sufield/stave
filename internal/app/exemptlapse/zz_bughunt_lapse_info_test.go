package exemptlapse

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Lapse_SeverityInfoBumped(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID:       kernel.ControlID("CTL.A.001"),
			AssetID:         asset.ID("asset1"),
			ControlSeverity: policy.SeverityInfo,
			Status:          evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:          "acknowledgment",
				ExpiryDate:    "2026-03-01",
				Valid:         false,
				InvalidReason: "expired",
			},
		},
	}

	result := Detect(Input{
		Findings: findings,
		EvalTime: time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}

	if result[0].OriginalSeverity != policy.SeverityInfo {
		t.Errorf("original severity = %v, want info", result[0].OriginalSeverity)
	}

	if result[0].Severity != policy.SeverityLow {
		t.Errorf("severity = %v, want low (bumped from info)", result[0].Severity)
	}
}
