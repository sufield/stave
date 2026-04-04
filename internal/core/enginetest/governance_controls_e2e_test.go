package enginetest

// E2E tests for CTL.S3.GOVERNANCE.001 (Data Classification Tag Required).
// Fires when kind=bucket AND tags.data-classification is missing.

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

// --- Fixture helpers ---

func govBucket(id string, tags map[string]any) asset.Asset {
	storage := map[string]any{"kind": "bucket"}
	if tags != nil {
		storage["tags"] = tags
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

func govSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadGovernanceControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	for _, ctl := range all {
		if ctl.ID == "CTL.S3.GOVERNANCE.001" {
			return []policy.ControlDefinition{ctl}
		}
	}
	t.Fatalf("control CTL.S3.GOVERNANCE.001 not found")
	return nil
}

func govEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadGovernanceControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasGovFinding(t *testing.T, result evaluation.Result, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == "CTL.S3.GOVERNANCE.001" && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding CTL.S3.GOVERNANCE.001 for asset %s, got %d findings", assetID, len(result.Findings))
}

func assertNoGovFinding(t *testing.T, result evaluation.Result, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == "CTL.S3.GOVERNANCE.001" && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding CTL.S3.GOVERNANCE.001 for asset %s", assetID)
			return
		}
	}
}

func TestGovernance001_TruePositive_NoClassificationTag(t *testing.T) {
	ev := govEvaluator(t)
	bucket := govBucket("untagged-bucket", nil)

	result := ev.Evaluate(govSnapshot(bucket))

	assertHasGovFinding(t, result, "untagged-bucket")
}

func TestGovernance001_TrueNegative_HasClassificationTag(t *testing.T) {
	ev := govEvaluator(t)
	bucket := govBucket("tagged-bucket", map[string]any{
		"data-classification": "internal",
	})

	result := ev.Evaluate(govSnapshot(bucket))

	assertNoGovFinding(t, result, "tagged-bucket")
}
