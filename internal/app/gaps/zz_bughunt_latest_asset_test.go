package gaps

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func TestBugHunt_Gaps_LatestPerAsset(t *testing.T) {
	// Snapshot 0 (oldest): has asset-1 with status "old"
	t0 := time.Now().Add(-2 * time.Hour)
	snap0 := asset.Snapshot{
		CapturedAt: t0,
		Assets: []asset.Asset{
			{
				ID:   "asset-1",
				Type: "compute",
				Properties: map[string]any{
					"status": "old",
				},
			},
		},
	}

	// Snapshot 1 (newer): has asset-1 with status "new"
	t1 := time.Now().Add(-1 * time.Hour)
	snap1 := asset.Snapshot{
		CapturedAt: t1,
		Assets: []asset.Asset{
			{
				ID:   "asset-1",
				Type: "compute",
				Properties: map[string]any{
					"status": "new",
				},
			},
		},
	}

	// Snapshot 2 (latest overall): does not contain asset-1
	t2 := time.Now()
	snap2 := asset.Snapshot{
		CapturedAt: t2,
		Assets: []asset.Asset{
			{
				ID:   "asset-2",
				Type: "compute",
				Properties: map[string]any{
					"status": "other",
				},
			},
		},
	}

	snapshots := []asset.Snapshot{snap0, snap1, snap2}
	latest := latestPerAsset(snapshots)

	a1, ok := latest["asset-1"]
	if !ok {
		t.Fatalf("expected asset-1 to be present in latestPerAsset map")
	}

	status, _ := a1.Properties["status"].(string)
	if status != "new" {
		t.Errorf("expected latest asset-1 to have status 'new' (from snap1), but got %q (likely retained old snap0 due to snapshotOf bug)", status)
	}
}
