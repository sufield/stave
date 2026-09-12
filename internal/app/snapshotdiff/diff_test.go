package snapshotdiff

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/diff"
	"github.com/sufield/stave/internal/core/kernel"
)

var (
	tBefore = time.Date(2026, 2, 13, 2, 0, 0, 0, time.UTC)
	tAfter  = time.Date(2026, 2, 14, 2, 0, 0, 0, time.UTC)
)

func TestDiff_ChangedPropertyDetected(t *testing.T) {
	before := asset.Snapshot{
		CapturedAt: tBefore,
		Assets: []asset.Asset{
			{
				ID: "arn:aws:s3:::prod-bucket", Type: kernel.AssetType("s3_bucket"),
				Properties: map[string]any{
					"public_access_block": map[string]any{
						"block_public_acls": true,
					},
				},
			},
		},
	}
	after := asset.Snapshot{
		CapturedAt: tAfter,
		Assets: []asset.Asset{
			{
				ID: "arn:aws:s3:::prod-bucket", Type: kernel.AssetType("s3_bucket"),
				Properties: map[string]any{
					"public_access_block": map[string]any{
						"block_public_acls": false,
					},
				},
			},
		},
	}

	result := Diff(before, after)

	if len(result.PropertyChanges) != 1 {
		t.Fatalf("changes = %d, want 1", len(result.PropertyChanges))
	}
	c := result.PropertyChanges[0]
	if c.Property != "public_access_block.block_public_acls" {
		t.Errorf("property = %s, want public_access_block.block_public_acls", c.Property)
	}
	if c.Before != true || c.After != false {
		t.Errorf("values = %v → %v, want true → false", c.Before, c.After)
	}
}

func TestDiff_UnchangedPropertyNotInOutput(t *testing.T) {
	before := asset.Snapshot{
		CapturedAt: tBefore,
		Assets: []asset.Asset{
			{
				ID: "bucket1", Type: "s3_bucket",
				Properties: map[string]any{"region": "us-east-1", "versioning": true},
			},
		},
	}
	after := asset.Snapshot{
		CapturedAt: tAfter,
		Assets: []asset.Asset{
			{
				ID: "bucket1", Type: "s3_bucket",
				Properties: map[string]any{"region": "us-east-1", "versioning": true},
			},
		},
	}

	result := Diff(before, after)

	if len(result.PropertyChanges) != 0 {
		t.Errorf("changes = %d, want 0", len(result.PropertyChanges))
	}
}

func TestDiff_NewAssetDetected(t *testing.T) {
	before := asset.Snapshot{
		CapturedAt: tBefore,
		Assets:     []asset.Asset{},
	}
	after := asset.Snapshot{
		CapturedAt: tAfter,
		Assets: []asset.Asset{
			{
				ID: "arn:aws:ec2:us-east-1:123:instance/i-new", Type: "ec2_instance",
				Properties: map[string]any{"public_ip": "203.0.113.42"},
			},
		},
	}

	result := Diff(before, after)

	if len(result.NewAssets) != 1 {
		t.Fatalf("new assets = %d, want 1", len(result.NewAssets))
	}
	if result.NewAssets[0].AssetID != "arn:aws:ec2:us-east-1:123:instance/i-new" {
		t.Errorf("new asset = %s, want i-new", result.NewAssets[0].AssetID)
	}
}

func TestDiff_RemovedAssetDetected(t *testing.T) {
	before := asset.Snapshot{
		CapturedAt: tBefore,
		Assets: []asset.Asset{
			{ID: "old-bucket", Type: "s3_bucket", Properties: map[string]any{}},
		},
	}
	after := asset.Snapshot{
		CapturedAt: tAfter,
		Assets:     []asset.Asset{},
	}

	result := Diff(before, after)

	if len(result.RemovedAssets) != 1 {
		t.Fatalf("removed = %d, want 1", len(result.RemovedAssets))
	}
	if result.RemovedAssets[0].AssetID != "old-bucket" {
		t.Errorf("removed = %s, want old-bucket", result.RemovedAssets[0].AssetID)
	}
}

func TestDiff_DeterministicOutput(t *testing.T) {
	before := asset.Snapshot{
		CapturedAt: tBefore,
		Assets: []asset.Asset{
			{ID: "b-asset", Type: "s3", Properties: map[string]any{"x": 1}},
			{ID: "a-asset", Type: "s3", Properties: map[string]any{"x": 1}},
		},
	}
	after := asset.Snapshot{
		CapturedAt: tAfter,
		Assets: []asset.Asset{
			{ID: "a-asset", Type: "s3", Properties: map[string]any{"x": 2}},
			{ID: "b-asset", Type: "s3", Properties: map[string]any{"x": 2}},
		},
	}

	result := Diff(before, after)

	if len(result.PropertyChanges) != 2 {
		t.Fatalf("changes = %d, want 2", len(result.PropertyChanges))
	}
	// Should be sorted by asset ID (a before b).
	if result.PropertyChanges[0].AssetID != "a-asset" {
		t.Errorf("first change asset = %s, want a-asset", result.PropertyChanges[0].AssetID)
	}
}

func TestBugHunt_Diff_NumericTypeCoercion(t *testing.T) {
	before := asset.Snapshot{
		CapturedAt: tBefore,
		Assets: []asset.Asset{
			{ID: "asset-1", Type: "s3", Properties: map[string]any{"x": 1}}, // int
		},
	}
	after := asset.Snapshot{
		CapturedAt: tAfter,
		Assets: []asset.Asset{
			{ID: "asset-1", Type: "s3", Properties: map[string]any{"x": 1.0}}, // float64
		},
	}

	result := Diff(before, after)
	if len(result.PropertyChanges) != 0 {
		t.Errorf("expected 0 property changes because 1 and 1.0 are numerically equal, but got %d: %+v",
			len(result.PropertyChanges), result.PropertyChanges)
	}
}

func TestPropertyChanges_CollectionMethods(t *testing.T) {
	pcs := PropertyChanges{
		{Property: "p1", RiskDirection: diff.RiskIncreasing},
		{Property: "p2", RiskDirection: diff.RiskDecreasing},
		{Property: "p1", RiskDirection: diff.RiskNeutral},
	}

	if pcs.Len() != 3 {
		t.Errorf("pcs.Len() = %d, want 3", pcs.Len())
	}

	if pcs.RiskIncreasing().Len() != 1 {
		t.Errorf("RiskIncreasing len = %d, want 1", pcs.RiskIncreasing().Len())
	}

	if pcs.RiskDecreasing().Len() != 1 {
		t.Errorf("RiskDecreasing len = %d, want 1", pcs.RiskDecreasing().Len())
	}

	if pcs.ByProperty("p1").Len() != 2 {
		t.Errorf("ByProperty(p1) len = %d, want 2", pcs.ByProperty("p1").Len())
	}
}
