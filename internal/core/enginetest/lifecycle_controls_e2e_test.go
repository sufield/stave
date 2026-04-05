package enginetest

// E2E tests for S3 Lifecycle controls (LIFECYCLE.001, LIFECYCLE.002).
//   - LIFECYCLE.001: retention-tagged bucket + lifecycle.rules_configured=false → violation
//   - LIFECYCLE.002: PHI bucket + has_expiration=true + min_expiration_days < 2190 → violation

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

func lifecycleBucket(id string, lifecycle map[string]any, tags map[string]any) asset.Asset {
	storage := map[string]any{"kind": "bucket"}
	if lifecycle != nil {
		storage["lifecycle"] = lifecycle
	}
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

func lifecycleSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadLifecycleControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.LIFECYCLE.001": {},
		"CTL.S3.LIFECYCLE.002": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d lifecycle controls, found %d", len(ids), len(controls))
	}
	return controls
}

func lifecycleEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadLifecycleControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasLifecycleFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoLifecycleFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- LIFECYCLE.001: Retention-Tagged Buckets Must Have Lifecycle Rules ---
// Gated by: tags.data-retention present

func TestLifecycle001_TruePositive_RetentionTaggedNoRules(t *testing.T) {
	ev := lifecycleEvaluator(t)
	bucket := lifecycleBucket("no-rules-bucket", map[string]any{
		"rules_configured": false,
	}, map[string]any{
		"data-retention": "7-years",
	})

	result := ev.Evaluate(lifecycleSnapshot(bucket))

	assertHasLifecycleFinding(t, result, "CTL.S3.LIFECYCLE.001", "no-rules-bucket")
}

func TestLifecycle001_TrueNegative_RetentionTaggedWithRules(t *testing.T) {
	ev := lifecycleEvaluator(t)
	bucket := lifecycleBucket("rules-bucket", map[string]any{
		"rules_configured": true,
	}, map[string]any{
		"data-retention": "7-years",
	})

	result := ev.Evaluate(lifecycleSnapshot(bucket))

	assertNoLifecycleFinding(t, result, "CTL.S3.LIFECYCLE.001", "rules-bucket")
}

func TestLifecycle001_TrueNegative_NoRetentionTag(t *testing.T) {
	ev := lifecycleEvaluator(t)
	// No data-retention tag — control should not fire
	bucket := lifecycleBucket("untagged-bucket", map[string]any{
		"rules_configured": false,
	}, nil)

	result := ev.Evaluate(lifecycleSnapshot(bucket))

	assertNoLifecycleFinding(t, result, "CTL.S3.LIFECYCLE.001", "untagged-bucket")
}

// --- LIFECYCLE.002: PHI Buckets Must Not Expire Data Before Minimum Retention ---
// Gated by: tags.data-classification=phi AND has_expiration=true
// Unsafe when: min_expiration_days < params.min_retention_days (2190)

func TestLifecycle002_TruePositive_PHIShortExpiration(t *testing.T) {
	ev := lifecycleEvaluator(t)
	bucket := lifecycleBucket("short-exp-bucket", map[string]any{
		"has_expiration":      true,
		"min_expiration_days": 365,
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lifecycleSnapshot(bucket))

	assertHasLifecycleFinding(t, result, "CTL.S3.LIFECYCLE.002", "short-exp-bucket")
}

func TestLifecycle002_TrueNegative_PHISufficientExpiration(t *testing.T) {
	ev := lifecycleEvaluator(t)
	bucket := lifecycleBucket("long-exp-bucket", map[string]any{
		"has_expiration":      true,
		"min_expiration_days": 2555,
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lifecycleSnapshot(bucket))

	assertNoLifecycleFinding(t, result, "CTL.S3.LIFECYCLE.002", "long-exp-bucket")
}

func TestLifecycle002_TrueNegative_PHINoExpiration(t *testing.T) {
	ev := lifecycleEvaluator(t)
	// has_expiration=false — control should not fire
	bucket := lifecycleBucket("no-exp-bucket", map[string]any{
		"has_expiration":      false,
		"min_expiration_days": 30,
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lifecycleSnapshot(bucket))

	assertNoLifecycleFinding(t, result, "CTL.S3.LIFECYCLE.002", "no-exp-bucket")
}

func TestLifecycle002_TrueNegative_NonPHIBucket(t *testing.T) {
	ev := lifecycleEvaluator(t)
	// Not PHI — control should not fire
	bucket := lifecycleBucket("internal-bucket", map[string]any{
		"has_expiration":      true,
		"min_expiration_days": 30,
	}, map[string]any{
		"data-classification": "internal",
	})

	result := ev.Evaluate(lifecycleSnapshot(bucket))

	assertNoLifecycleFinding(t, result, "CTL.S3.LIFECYCLE.002", "internal-bucket")
}
