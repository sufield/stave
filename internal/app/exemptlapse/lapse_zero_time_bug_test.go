package exemptlapse

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestDetect_ZeroEvalTimeDefaultedToNowForSeverityBump(t *testing.T) {
	// Exemption expired 60 days ago
	expiredDate := time.Now().Add(-60 * 24 * time.Hour).Format("2006-01-02")

	f := evaluation.Finding{
		ControlID:       kernel.ControlID("CTL.S3.001"),
		AssetID:         asset.ID("my-bucket"),
		ControlSeverity: policy.SeverityMedium,
		Status:          evaluation.FindingSuppressed,
		Suppression: &evaluation.Suppression{
			Valid:         false,
			InvalidReason: "expired",
			ExpiryDate:    expiredDate,
		},
	}

	in := Input{
		Findings: []evaluation.Finding{f},
		EvalTime: time.Time{}, // zero EvalTime
	}

	lapsed := Detect(in)
	if len(lapsed) != 1 {
		t.Fatalf("expected 1 lapsed finding, got %d", len(lapsed))
	}

	// Because it expired 60 days ago (> severityBumpThresholdDays), severity must be bumped from MEDIUM to HIGH
	if lapsed[0].Severity != policy.SeverityHigh {
		t.Errorf("expected bumped severity %v when EvalTime is zero, got %v", policy.SeverityHigh, lapsed[0].Severity)
	}
}
