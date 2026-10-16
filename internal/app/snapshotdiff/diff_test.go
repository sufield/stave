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

func TestNewAndRemovedAssets_DomainMethods(t *testing.T) {
	newAssets := NewAssets{
		{AssetID: "a1", AssetType: "aws_s3_bucket"},
		{AssetID: "a2", AssetType: "aws_iam_role"},
		{AssetID: "a3", AssetType: "aws_s3_bucket"},
	}

	if newAssets.Len() != 3 {
		t.Errorf("newAssets.Len() = %d, want 3", newAssets.Len())
	}
	if newAssets.ByType("aws_s3_bucket").Len() != 2 {
		t.Errorf("newAssets.ByType(aws_s3_bucket).Len() = %d, want 2", newAssets.ByType("aws_s3_bucket").Len())
	}

	removedAssets := RemovedAssets{
		{AssetID: "r1", AssetType: "aws_ec2_instance"},
	}

	if removedAssets.Len() != 1 {
		t.Errorf("removedAssets.Len() = %d, want 1", removedAssets.Len())
	}
	if removedAssets.ByType("aws_ec2_instance").Len() != 1 {
		t.Errorf("removedAssets.ByType(aws_ec2_instance).Len() = %d, want 1", removedAssets.ByType("aws_ec2_instance").Len())
	}

	var emptyNew NewAssets
	if emptyNew.Len() != 0 {
		t.Errorf("emptyNew.Len() = %d, want 0", emptyNew.Len())
	}
	if emptyNew.ByType("aws_s3_bucket") != nil {
		t.Error("emptyNew.ByType() should return nil")
	}

	var emptyRemoved RemovedAssets
	if emptyRemoved.Len() != 0 {
		t.Errorf("emptyRemoved.Len() = %d, want 0", emptyRemoved.Len())
	}
	if emptyRemoved.ByType("aws_ec2_instance") != nil {
		t.Error("emptyRemoved.ByType() should return nil")
	}
}

func TestRiskSummary_DomainMethods(t *testing.T) {
	// Zero/empty
	var empty RiskSummary
	if empty.Total() != 0 {
		t.Errorf("empty.Total() = %d, want 0", empty.Total())
	}
	if empty.HasRiskChanges() {
		t.Error("empty.HasRiskChanges() = true, want false")
	}
	if empty.NetRisk() != 0 {
		t.Errorf("empty.NetRisk() = %d, want 0", empty.NetRisk())
	}
	if !empty.IsRiskNeutral() {
		t.Error("empty.IsRiskNeutral() = false, want true")
	}

	// Net increasing
	inc := RiskSummary{Increasing: 5, Decreasing: 2, Neutral: 3}
	if inc.Total() != 10 {
		t.Errorf("inc.Total() = %d, want 10", inc.Total())
	}
	if !inc.HasRiskChanges() {
		t.Error("inc.HasRiskChanges() = false, want true")
	}
	if inc.NetRisk() != 3 {
		t.Errorf("inc.NetRisk() = %d, want 3", inc.NetRisk())
	}
	if !inc.IsNetRiskIncreasing() {
		t.Error("inc.IsNetRiskIncreasing() = false, want true")
	}
	if inc.IsNetRiskDecreasing() {
		t.Error("inc.IsNetRiskDecreasing() = true, want false")
	}
	if inc.IsRiskNeutral() {
		t.Error("inc.IsRiskNeutral() = true, want false")
	}

	// Net decreasing
	dec := RiskSummary{Increasing: 1, Decreasing: 4, Neutral: 0}
	if dec.NetRisk() != -3 {
		t.Errorf("dec.NetRisk() = %d, want -3", dec.NetRisk())
	}
	if !dec.IsNetRiskDecreasing() {
		t.Error("dec.IsNetRiskDecreasing() = false, want true")
	}
	if dec.IsNetRiskIncreasing() {
		t.Error("dec.IsNetRiskIncreasing() = true, want false")
	}
}

func TestDiffResult_DomainMethods(t *testing.T) {
	var nilResult *DiffResult
	if nilResult.HasDifferences() {
		t.Error("nilResult.HasDifferences() = true, want false")
	}
	if nilResult.TotalDifferences() != 0 {
		t.Errorf("nilResult.TotalDifferences() = %d, want 0", nilResult.TotalDifferences())
	}
	if nilResult.AssetCountDelta() != 0 {
		t.Errorf("nilResult.AssetCountDelta() = %d, want 0", nilResult.AssetCountDelta())
	}

	empty := &DiffResult{BeforeAssets: 5, AfterAssets: 5}
	if empty.HasDifferences() {
		t.Error("empty.HasDifferences() = true, want false")
	}
	if empty.TotalDifferences() != 0 {
		t.Errorf("empty.TotalDifferences() = %d, want 0", empty.TotalDifferences())
	}
	if empty.AssetCountDelta() != 0 {
		t.Errorf("empty.AssetCountDelta() = %d, want 0", empty.AssetCountDelta())
	}

	withDiffs := &DiffResult{
		BeforeAssets: 10,
		AfterAssets:  12,
		PropertyChanges: PropertyChanges{
			{AssetID: "a1", Property: "p1"},
		},
		NewAssets: NewAssets{
			{AssetID: "a2"},
			{AssetID: "a3"},
		},
	}
	if !withDiffs.HasDifferences() {
		t.Error("withDiffs.HasDifferences() = false, want true")
	}
	if withDiffs.TotalDifferences() != 3 {
		t.Errorf("withDiffs.TotalDifferences() = %d, want 3", withDiffs.TotalDifferences())
	}
	if withDiffs.AssetCountDelta() != 2 {
		t.Errorf("withDiffs.AssetCountDelta() = %d, want 2", withDiffs.AssetCountDelta())
	}
}
