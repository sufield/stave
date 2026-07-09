package readiness

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Analyze_UnsortedSnapshots_UsesChronologicallyLatest(t *testing.T) {
	// snap1 is older (captured 24 hours ago) and has an S3 bucket.
	snap1 := asset.Snapshot{
		CapturedAt: time.Now().Add(-24 * time.Hour),
		Assets: []asset.Asset{
			{
				ID:   "arn:aws:s3:::old-bucket",
				Type: kernel.AssetType("aws_s3_bucket"),
			},
		},
	}

	// snap2 is newer (captured now) and has no assets.
	snap2 := asset.Snapshot{
		CapturedAt: time.Now(),
		Assets:     []asset.Asset{},
	}

	controls := []policy.ControlDefinition{
		{
			ID:                   "CTL.S3.001",
			ApplicableAssetTypes: []kernel.AssetType{"aws_s3_bucket"},
		},
	}

	// We pass the snapshots in unsorted order (newer snap2 first, older snap1 last).
	// Under the buggy code, the analyzer picks the last element (snap1) as the latest
	// and incorrectly thinks aws_s3_bucket is observed.
	report := Analyze(controls, nil, []asset.Snapshot{snap2, snap1}, 5)

	if _, ok := report.ObservedTypes["aws_s3_bucket"]; ok {
		t.Errorf("expected aws_s3_bucket NOT to be observed (deleted in chronologically latest snapshot), but it was included because snapshots slice wasn't sorted chronologically")
	}
}
