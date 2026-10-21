package exemptlapse

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

var now = time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

func TestDetect_ExpiredExemptionProducesLapsed(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"),
			AssetID:   asset.ID("arn:aws:s3:::prod-bucket"),
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:             "acknowledgment",
				ExpiryDate:       "2026-01-01",
				AcknowledgedDate: "2025-10-01",
				Valid:            false,
				InvalidReason:    "expired",
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}
	if result[0].FindingType != "EXEMPTION_LAPSED" {
		t.Errorf("type = %s, want EXEMPTION_LAPSED", result[0].FindingType)
	}
	if result[0].DaysSinceExpiry < 100 {
		t.Errorf("days = %d, want >= 100", result[0].DaysSinceExpiry)
	}
}

func TestDetect_SeverityBumpAfter30Days(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			AssetID:   "asset1",
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:          "acknowledgment",
				ExpiryDate:    "2026-03-01",
				Valid:         false,
				InvalidReason: "expired",
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}
	if result[0].Severity == result[0].OriginalSeverity {
		t.Error("severity should be bumped after 30+ days past expiry")
	}
	if result[0].SeverityBumpReason == "" {
		t.Error("bump reason should be set")
	}
}

func TestDetect_CompensatingControlFailureSurfaces(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			AssetID:   "asset1",
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:          "acknowledgment",
				ExpiryDate:    "2026-05-01",
				Valid:         false,
				InvalidReason: "compensating_controls_failing",
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 1 {
		t.Fatalf("lapsed = %d, want 1", len(result))
	}
	if result[0].CompensatingNote == "" {
		t.Error("compensating note should be set")
	}
}

func TestDetect_ActiveExemptionStillSuppresses(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			AssetID:   "asset1",
			Status:    evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:       "acknowledgment",
				ExpiryDate: "2026-12-31",
				Valid:      true,
			},
		},
	}

	result := Detect(Input{Findings: findings, EvalTime: now})

	if len(result) != 0 {
		t.Errorf("lapsed = %d, want 0 (active exemption)", len(result))
	}
}
