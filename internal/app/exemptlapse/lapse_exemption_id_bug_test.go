package exemptlapse

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestDetect_DistinctAssetTypesUniqueExemptionIDs(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			AssetID:         asset.ID("arn:aws:s3:::my-resource"),
			AssetType:       kernel.AssetType("aws_s3_bucket"),
			Status:          evaluation.FindingSuppressed,
			ControlSeverity: policy.SeverityHigh,
			Suppression: &evaluation.Suppression{
				Valid:         false,
				InvalidReason: "expired",
				ExpiryDate:    "2026-01-01",
			},
		},
		{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			AssetID:         asset.ID("arn:aws:s3:::my-resource"),
			AssetType:       kernel.AssetType("aws_s3_access_point"),
			Status:          evaluation.FindingSuppressed,
			ControlSeverity: policy.SeverityHigh,
			Suppression: &evaluation.Suppression{
				Valid:         false,
				InvalidReason: "expired",
				ExpiryDate:    "2026-01-01",
			},
		},
	}

	in := Input{
		Findings: findings,
		EvalTime: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}

	lapsed := Detect(in)
	if len(lapsed) != 2 {
		t.Fatalf("expected 2 lapsed findings, got %d", len(lapsed))
	}

	if lapsed[0].ExemptionID == lapsed[1].ExemptionID {
		t.Fatalf("duplicate ExemptionID for different AssetTypes: %s", lapsed[0].ExemptionID)
	}
}
