package diff

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
)

func TestComputeObservationDelta_DetectsAddedRemovedModified(t *testing.T) {
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	prev := asset.Snapshot{
		CapturedAt: t1,
		Assets: []asset.Asset{
			{
				ID:     "res-a",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": false,
					"tags": map[string]any{
						"owner": "team-a",
					},
				},
			},
			{
				ID:     "res-b",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": true,
				},
			},
		},
	}

	curr := asset.Snapshot{
		CapturedAt: t2,
		Assets: []asset.Asset{
			{
				ID:     "res-a",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": true,
					"tags": map[string]any{
						"owner": "team-b",
					},
				},
			},
			{
				ID:     "res-c",
				Type:   "bucket",
				Vendor: "aws",
				Properties: map[string]any{
					"public": false,
				},
			},
		},
	}

	out := asset.ComputeObservationDelta(prev, curr)
	if out.Summary.Added() != 1 || out.Summary.Removed() != 1 || out.Summary.Modified() != 1 {
		t.Fatalf("unexpected summary: %+v", out.Summary)
	}
	if len(out.Changes) != 3 {
		t.Fatalf("expected 3 resource changes, got %d", len(out.Changes))
	}
}

func TestLatestTwoSnapshots_SelectsMostRecentByCapturedAt(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	in := []asset.Snapshot{{CapturedAt: t2}, {CapturedAt: t1}, {CapturedAt: t3}}
	prev, curr, err := asset.LatestTwoSnapshots(in)
	if err != nil {
		t.Fatalf("LatestTwoSnapshots returned error: %v", err)
	}
	if !prev.CapturedAt.Equal(t2) || !curr.CapturedAt.Equal(t3) {
		t.Fatalf("expected latest two snapshots t2,t3; got %s,%s", prev.CapturedAt, curr.CapturedAt)
	}
}

func TestNewDiffFilter_InvalidChangeType(t *testing.T) {
	_, err := newDiffFilter([]string{"update"}, nil, "")
	if err == nil {
		t.Fatal("expected invalid change type error")
	}
}

func TestApplyDiffFilter(t *testing.T) {
	changes := []asset.AssetDiff{
		{AssetID: "bucket-a", ChangeType: asset.ChangeAdded, ToType: "res:aws:s3:bucket"},
		{AssetID: "bucket-b", ChangeType: asset.ChangeModified, FromType: "res:aws:s3:bucket", ToType: "res:aws:s3:bucket"},
		{AssetID: "queue-a", ChangeType: asset.ChangeRemoved, FromType: "res:aws:sqs:queue"},
	}
	filter, err := newDiffFilter([]string{"modified", "removed"}, []string{"res:aws:s3:bucket"}, "bucket")
	if err != nil {
		t.Fatalf("newDiffFilter returned error: %v", err)
	}
	delta := asset.ObservationDelta{Changes: changes}
	filtered := delta.ApplyFilter(filter)
	if len(filtered.Changes) != 1 {
		t.Fatalf("expected 1 filtered change, got %d", len(filtered.Changes))
	}
	if filtered.Changes[0].AssetID != "bucket-b" {
		t.Fatalf("unexpected filtered resource: %+v", filtered.Changes[0])
	}
	summary := filtered.Summary
	if summary.Modified() != 1 || summary.Total() != 1 || summary.Added() != 0 || summary.Removed() != 0 {
		t.Fatalf("unexpected filtered summary: %+v", summary)
	}
}
