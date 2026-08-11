package engine

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestBuildLifecycles_AssetTypeGate confirms the asset-type gate runs
// before predicate evaluation in BuildLifecyclesPerControl.
//
// Two controls share an asset's vendor:
//   - CTL.A applies to s3_bucket only (declared via ApplicableAssetTypes)
//   - CTL.B applies to all asset types (legacy default — no declaration)
//
// The asset is an ec2_instance. CTL.A must be skipped silently (no
// lifecycle entry, no inconclusive); CTL.B must evaluate.
func TestBuildLifecycles_AssetTypeGate(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		{
			ID:                   "CTL.A.001",
			Type:                 policy.TypeUnsafeState,
			ScopeTags:            []kernel.ScopeTag{"aws"},
			ApplicableAssetTypes: []kernel.AssetType{"s3_bucket"},
		},
		{
			ID:        "CTL.B.001",
			Type:      policy.TypeUnsafeState,
			ScopeTags: []kernel.ScopeTag{"aws"},
			// No ApplicableAssetTypes → fires on every asset type.
		},
	}
	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets: []asset.Asset{{
				ID:     "instance-1",
				Type:   "ec2_instance",
				Vendor: "aws",
			}},
		},
	}

	// Predicate evaluator records which (control, asset) pairs the engine
	// asks it to evaluate. The gate must filter CTL.A before this is
	// invoked for the ec2_instance asset.
	var evaluated []string
	celEval := func(c *policy.ControlDefinition, a asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		evaluated = append(evaluated, string(c.ID)+"|"+string(a.ID))
		return false, nil
	}

	lifecycles, err := BuildLifecyclesPerControl(context.Background(), controls, snapshots, celEval)
	if err != nil {
		t.Fatalf("BuildLifecyclesPerControl: %v", err)
	}

	// CTL.A must NOT have been evaluated for instance-1.
	for _, e := range evaluated {
		if e == "CTL.A.001|instance-1" {
			t.Errorf("CTL.A.001 was evaluated for ec2_instance despite ApplicableAssetTypes=[s3_bucket]; gate did not run before predicate")
		}
	}

	// CTL.B must HAVE been evaluated.
	bEvaluated := false
	for _, e := range evaluated {
		if e == "CTL.B.001|instance-1" {
			bEvaluated = true
		}
	}
	if !bEvaluated {
		t.Errorf("CTL.B.001 (no ApplicableAssetTypes) should fire on all asset types; was not evaluated for ec2_instance")
	}

	// CTL.A must have NO lifecycle entry for instance-1 — silent skip means
	// the lifecycle map should be empty for that (control, asset) pair.
	if entry, ok := lifecycles["CTL.A.001"]["instance-1"]; ok {
		t.Errorf("CTL.A.001 produced a lifecycle entry for instance-1: %+v; gate must skip silently (no entry, no inconclusive)", entry)
	}

	// CTL.B must have a lifecycle entry.
	if _, ok := lifecycles["CTL.B.001"]["instance-1"]; !ok {
		t.Errorf("CTL.B.001 did not produce a lifecycle entry for instance-1; legacy default (no ApplicableAssetTypes) should fire")
	}
}

// TestBuildLifecycles_AssetTypeGate_MatchingAsset confirms a matching
// asset type still evaluates normally (gate passes through).
func TestBuildLifecycles_AssetTypeGate_MatchingAsset(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		{
			ID:                   "CTL.A.001",
			Type:                 policy.TypeUnsafeState,
			ScopeTags:            []kernel.ScopeTag{"aws"},
			ApplicableAssetTypes: []kernel.AssetType{"s3_bucket"},
		},
	}
	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets: []asset.Asset{{
				ID:     "bucket-1",
				Type:   "s3_bucket",
				Vendor: "aws",
			}},
		},
	}
	celEval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil // unsafe
	}

	lifecycles, err := BuildLifecyclesPerControl(context.Background(), controls, snapshots, celEval)
	if err != nil {
		t.Fatalf("BuildLifecyclesPerControl: %v", err)
	}

	tl, ok := lifecycles["CTL.A.001"]["bucket-1"]
	if !ok {
		t.Fatal("CTL.A.001 should have evaluated bucket-1 (matching asset type)")
	}
	if !tl.IsExposed() {
		t.Errorf("bucket-1 lifecycle should be unsafe; predicate returned true")
	}
}
