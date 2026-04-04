package enginetest

// E2E tests for S3 Misc controls (CONTROLS.001, INCOMPLETE.001).
//   - CONTROLS.001: kind=bucket AND controls.public_access_fully_blocked=false → violation (unsafe_state)
//   - INCOMPLETE.001: safety_provable=false → violation (unsafe_duration with max_unsafe_duration=0h)

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

func miscBucketWithControls(id string, controls map[string]any) asset.Asset {
	storage := map[string]any{"kind": "bucket"}
	if controls != nil {
		storage["controls"] = controls
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": storage,
		},
	}
}

func miscIncompleteAsset(id string, safetyProvable bool) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"safety_provable": safetyProvable,
		},
	}
}

func miscSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadMiscControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.CONTROLS.001":   {},
		"CTL.S3.INCOMPLETE.001": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d misc controls, found %d", len(ids), len(controls))
	}
	return controls
}

func miscEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadMiscControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasMiscFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoMiscFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- CONTROLS.001: Public Access Block Must Be Enabled ---
// kind=bucket AND controls.public_access_fully_blocked=false

func TestControls001_TruePositive_PABNotFullyBlocked(t *testing.T) {
	ev := miscEvaluator(t)
	bucket := miscBucketWithControls("no-pab-bucket", map[string]any{
		"public_access_fully_blocked": false,
	})

	result := ev.Evaluate(miscSnapshot(bucket))

	assertHasMiscFinding(t, result, "CTL.S3.CONTROLS.001", "no-pab-bucket")
}

func TestControls001_TrueNegative_PABFullyBlocked(t *testing.T) {
	ev := miscEvaluator(t)
	bucket := miscBucketWithControls("pab-bucket", map[string]any{
		"public_access_fully_blocked": true,
	})

	result := ev.Evaluate(miscSnapshot(bucket))

	assertNoMiscFinding(t, result, "CTL.S3.CONTROLS.001", "pab-bucket")
}

// --- INCOMPLETE.001: Complete Data Required for Safety Assessment ---
// type: unsafe_duration (max_unsafe_duration=0h)
// safety_provable=false → violation

func TestIncomplete001_TruePositive_SafetyNotProvable(t *testing.T) {
	ev := miscEvaluator(t)
	a := miscIncompleteAsset("incomplete-bucket", false)

	result := ev.Evaluate(miscSnapshot(a))

	assertHasMiscFinding(t, result, "CTL.S3.INCOMPLETE.001", "incomplete-bucket")
}

func TestIncomplete001_TrueNegative_SafetyProvable(t *testing.T) {
	ev := miscEvaluator(t)
	a := miscIncompleteAsset("complete-bucket", true)

	result := ev.Evaluate(miscSnapshot(a))

	assertNoMiscFinding(t, result, "CTL.S3.INCOMPLETE.001", "complete-bucket")
}
