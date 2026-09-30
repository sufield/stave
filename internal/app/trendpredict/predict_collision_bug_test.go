package trendpredict

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func TestPredict_MTTRDoesNotCollideDistinctAssetTypesWithSameID(t *testing.T) {
	t0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(10 * 24 * time.Hour) // 10 days later

	// findingBucket is present at t0, fixed at t1 (MTTR = 10 days)
	findingBucket := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			AssetID:         asset.ID("shared-id"),
			AssetType:       kernel.AssetType("aws_s3_bucket"),
			ControlSeverity: policy.SeverityHigh,
		},
	}

	// findingRole is present at t0 AND STILL OPEN at t1 (not fixed!)
	findingRole := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID("CTL.S3.001"),
			AssetID:         asset.ID("shared-id"),
			AssetType:       kernel.AssetType("aws_iam_role"),
			ControlSeverity: policy.SeverityHigh,
		},
	}

	history := []*report.Assessment{
		{
			Run:      evaluation.RunInfo{EvalTime: t0},
			Findings: []remediation.Finding{findingBucket, findingRole},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t1},
			Findings: []remediation.Finding{findingRole}, // findingBucket fixed, findingRole still open
		},
	}

	// In computeMTTR:
	// findingBucket should be closed with MTTR = 10 days.
	// findingRole is NOT closed, so its fkey should remain open.
	// Without AssetType in fkey, findingBucket and findingRole collide, so fkey is NOT deleted because findingRole is in currentKeys at t1!
	// Thus closed slice has 0 entries, causing MTTR calculation to miss closed findings!

	mttr := computeMTTR(history, 30*24*time.Hour, t1)
	if len(mttr) == 0 {
		t.Fatalf("expected closed MTTR entry for resolved aws_s3_bucket finding, got empty MTTR map")
	}

	if mttr[policy.SeverityHigh] != 10.0 {
		t.Errorf("expected MTTR for high severity = 10 days, got %v", mttr[policy.SeverityHigh])
	}
}
