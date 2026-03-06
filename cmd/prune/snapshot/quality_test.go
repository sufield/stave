package snapshot

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
)

func TestAssessSnapshotQuality_NoSnapshots(t *testing.T) {
	report := assessQuality(qualityParams{
		Snapshots:         nil,
		Now:               time.Now().UTC(),
		MinSnapshots:      2,
		MaxStaleness:      48 * time.Hour,
		MaxGap:            7 * 24 * time.Hour,
		RequiredResources: nil,
		Strict:            false,
	})
	if report.Pass {
		t.Fatal("expected fail when no snapshots exist")
	}
	if len(report.Issues) == 0 || report.Issues[0].Code != "NO_SNAPSHOTS" {
		t.Fatalf("expected NO_SNAPSHOTS issue, got %+v", report.Issues)
	}
}

func TestAssessSnapshotQuality_StaleAndMissingRequired(t *testing.T) {
	now := time.Date(2026, 2, 22, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{
			CapturedAt: time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC),
			Resources: []asset.Asset{
				{ID: "res:1"},
			},
		},
	}

	report := assessQuality(qualityParams{
		Snapshots:         snapshots,
		Now:               now,
		MinSnapshots:      2,
		MaxStaleness:      24 * time.Hour,
		MaxGap:            7 * 24 * time.Hour,
		RequiredResources: []string{"res:1", "res:2"},
		Strict:            false,
	})

	if report.Pass {
		t.Fatal("expected fail for stale/too-few/missing-resource issues")
	}
	codes := map[string]bool{}
	for _, i := range report.Issues {
		codes[i.Code] = true
	}
	if !codes["TOO_FEW_SNAPSHOTS"] || !codes["LATEST_SNAPSHOT_STALE"] || !codes["MISSING_REQUIRED_RESOURCES"] {
		t.Fatalf("unexpected issues: %+v", report.Issues)
	}
}

func TestAssessSnapshotQuality_WarningStrictMode(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Resources: []asset.Asset{{ID: "res:1"}}},
		{CapturedAt: time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC), Resources: []asset.Asset{{ID: "res:1"}}},
	}

	reportWarn := assessQuality(qualityParams{
		Snapshots:    snapshots,
		Now:          now,
		MinSnapshots: 2,
		MaxStaleness: 30 * 24 * time.Hour,
		MaxGap:       24 * time.Hour,
		Strict:       false,
	})
	if !reportWarn.Pass {
		t.Fatalf("expected pass with warnings in non-strict mode, got fail: %+v", reportWarn)
	}

	reportStrict := assessQuality(qualityParams{
		Snapshots:    snapshots,
		Now:          now,
		MinSnapshots: 2,
		MaxStaleness: 30 * 24 * time.Hour,
		MaxGap:       24 * time.Hour,
		Strict:       true,
	})
	if reportStrict.Pass {
		t.Fatalf("expected strict mode fail on warning issue: %+v", reportStrict)
	}
}
