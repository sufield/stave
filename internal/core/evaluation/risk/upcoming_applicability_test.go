package risk

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestComputeItems_VendorScopedControlSkipsForeignVendor verifies that
// a control scoped to vendor "aws" produces no risk signals against
// an Azure asset, even when the predicate would match.
func TestComputeItems_VendorScopedControlSkipsForeignVendor(t *testing.T) {
	now := time.Now().UTC()
	ctl := policy.ControlDefinition{
		ID:        "CTL.AWS.A",
		Type:      policy.TypeUnsafeState,
		ScopeTags: []kernel.ScopeTag{"aws"},
	}
	snapshots := []asset.Snapshot{{
		CapturedAt: now.Add(-2 * time.Hour),
		Assets: []asset.Asset{
			{ID: "azure-asset", Type: "azure_storage", Vendor: "azure"},
		},
	}, {
		CapturedAt: now.Add(-1 * time.Hour),
		Assets: []asset.Asset{
			{ID: "azure-asset", Type: "azure_storage", Vendor: "azure"},
		},
	}}
	// Always-fires predicate. Without vendor filtering this would
	// generate a risk signal for the Azure asset.
	eval := policy.PredicateEval(func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	})

	items := ComputeItems(ThresholdRequest{
		Controls:                []policy.ControlDefinition{ctl},
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: 24 * time.Hour,
		Now:                     now,
		PredicateEval:           eval,
	})
	if len(items) != 0 {
		t.Errorf("got %d risk signals for foreign-vendor asset, want 0: %+v", len(items), items)
	}
}

// TestComputeItems_UniversalControlAppliesToAllVendors confirms a
// control with no scope tags still evaluates against every vendor.
func TestComputeItems_UniversalControlAppliesToAllVendors(t *testing.T) {
	now := time.Now().UTC()
	ctl := policy.ControlDefinition{
		ID:   "CTL.UNIVERSAL",
		Type: policy.TypeUnsafeState,
	}
	snapshots := []asset.Snapshot{{
		CapturedAt: now.Add(-2 * time.Hour),
		Assets: []asset.Asset{
			{ID: "azure-asset", Type: "azure_storage", Vendor: "azure"},
		},
	}, {
		CapturedAt: now.Add(-1 * time.Hour),
		Assets: []asset.Asset{
			{ID: "azure-asset", Type: "azure_storage", Vendor: "azure"},
		},
	}}
	eval := policy.PredicateEval(func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	})

	items := ComputeItems(ThresholdRequest{
		Controls:                []policy.ControlDefinition{ctl},
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: 24 * time.Hour,
		Now:                     now,
		PredicateEval:           eval,
	})
	if len(items) != 1 {
		t.Errorf("got %d risk signals from universal control, want 1: %+v", len(items), items)
	}
}

// TestComputeItems_ExemptedAssetSkippedFromRisk verifies that asset
// exemptions remove the asset from risk signals, mirroring the main
// finding pipeline's exemption check.
func TestComputeItems_ExemptedAssetSkippedFromRisk(t *testing.T) {
	now := time.Now().UTC()
	ctl := policy.ControlDefinition{
		ID:        "CTL.AWS.A",
		Type:      policy.TypeUnsafeState,
		ScopeTags: []kernel.ScopeTag{"aws"},
	}
	snapshots := []asset.Snapshot{{
		CapturedAt: now.Add(-2 * time.Hour),
		Assets: []asset.Asset{
			{ID: "exempted-id", Type: "aws_s3_bucket", Vendor: "aws"},
		},
	}, {
		CapturedAt: now.Add(-1 * time.Hour),
		Assets: []asset.Asset{
			{ID: "exempted-id", Type: "aws_s3_bucket", Vendor: "aws"},
		},
	}}
	eval := policy.PredicateEval(func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	})
	exemptions := policy.NewExemptionConfig("v1", []policy.ExemptionRule{
		{Pattern: "exempted-id", Reason: "test"},
	})

	items := ComputeItems(ThresholdRequest{
		Controls:                []policy.ControlDefinition{ctl},
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: 24 * time.Hour,
		Now:                     now,
		PredicateEval:           eval,
		Exemptions:              exemptions,
	})
	if len(items) != 0 {
		t.Errorf("got %d risk signals for exempted asset, want 0: %+v", len(items), items)
	}
}
