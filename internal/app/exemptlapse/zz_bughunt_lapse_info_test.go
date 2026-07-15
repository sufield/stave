package exemptlapse

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Lapse_SeverityInfoBumped(t *testing.T) {
	// Exemption for an "info" severity control has been expired for 45 days (> 30 days threshold)
	acknowledged := []policy.AcknowledgedFinding{
		{
			ControlID:     kernel.ControlID("CTL.A.001"),
			AssetID:       asset.ID("asset1"),
			ExpiryDate:    "2026-03-01", // 45 days before now (2026-04-15)
			Severity:      policy.SeverityInfo,
			Valid:         false,
			InvalidReason: "expired",
		},
	}

	result := Detect(Input{
		AcknowledgedFindings: acknowledged,
		EvalTime:             time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}

	// We expect the severity to be bumped from "info" to "low"
	if result[0].OriginalSeverity != "info" {
		t.Errorf("original severity = %s, want info", result[0].OriginalSeverity)
	}

	if result[0].Severity != "low" {
		t.Errorf("severity = %s, want low (bumped from info)", result[0].Severity)
	}
}
