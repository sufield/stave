package readiness

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Analyze_ExcludesStaleHistoricalAssets(t *testing.T) {
	// Snapshot 1 (older, captured 1 day ago) contains an S3 bucket
	snap1 := asset.Snapshot{
		CapturedAt: time.Now().Add(-24 * time.Hour),
		Assets: []asset.Asset{
			{
				ID:   "arn:aws:s3:::old-bucket",
				Type: kernel.AssetType("aws_s3_bucket"),
			},
		},
	}

	// Snapshot 2 (latest, captured now) has no assets (the bucket was deleted)
	snap2 := asset.Snapshot{
		CapturedAt: time.Now(),
		Assets:     []asset.Asset{},
	}

	controls := []policy.ControlDefinition{
		ctl("CTL.S3.001", "aws_s3_bucket"),
	}

	// Analyze both snapshots
	report := Analyze(controls, nil, []asset.Snapshot{snap1, snap2}, 5)

	// Since the bucket was deleted in the latest snapshot, no S3 buckets are active.
	// The readiness analyzer's documented intent is to count observed types from the
	// latest snapshot to prevent stale historical observations from inflating coverage.
	// Under the buggy code: it walks all snapshots, so it incorrectly reports aws_s3_bucket as observed.
	if _, ok := report.ObservedTypes["aws_s3_bucket"]; ok {
		t.Errorf("expected aws_s3_bucket NOT to be observed (deleted in latest snapshot), but it was included in observed types")
	}
}
