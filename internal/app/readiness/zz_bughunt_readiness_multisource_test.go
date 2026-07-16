package readiness

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Analyze_MultipleSourcesObserved(t *testing.T) {
	// Snapshot 1: older S3 snapshot (still active, no newer S3 snapshots exist)
	snap1 := asset.Snapshot{
		Source:     "aws_s3",
		CapturedAt: time.Now().Add(-24 * time.Hour),
		Assets: []asset.Asset{
			{
				ID:   "arn:aws:s3:::my-bucket",
				Type: kernel.AssetType("aws_s3_bucket"),
			},
		},
	}

	// Snapshot 2: newer IAM snapshot (active, captured now)
	snap2 := asset.Snapshot{
		Source:     "aws_iam",
		CapturedAt: time.Now(),
		Assets: []asset.Asset{
			{
				ID:   "arn:aws:iam::123456789012:role/my-role",
				Type: kernel.AssetType("aws_iam_role"),
			},
		},
	}

	controls := []policy.ControlDefinition{
		{
			ID:                   "CTL.S3.001",
			ApplicableAssetTypes: []kernel.AssetType{"aws_s3_bucket"},
		},
		{
			ID:                   "CTL.IAM.001",
			ApplicableAssetTypes: []kernel.AssetType{"aws_iam_role"},
		},
	}

	report := Analyze(controls, nil, []asset.Snapshot{snap1, snap2}, 5)

	// Under the buggy code: it only walks snap2 (latest), so aws_s3_bucket is missing.
	// Both S3 and IAM should be considered observed because they represent different sources.
	if _, ok := report.ObservedTypes["aws_s3_bucket"]; !ok {
		t.Errorf("expected aws_s3_bucket to be observed from snap1, but it was missing")
	}

	if _, ok := report.ObservedTypes["aws_iam_role"]; !ok {
		t.Errorf("expected aws_iam_role to be observed from snap2, but it was missing")
	}
}
