package enginetest

// E2E tests for S3 Takeover controls (BUCKET.TAKEOVER.001, DANGLING.ORIGIN.001).
//   - BUCKET.TAKEOVER.001: s3_ref.bucket_exists=false OR s3_ref.bucket_owned=false → violation
//     Note: uses any: (either condition fires), properties under s3_ref (not storage)
//   - DANGLING.ORIGIN.001: cdn.kind=distribution AND cdn.origins_has_dangling_s3=true → violation
//     Note: gated by cdn.kind, properties under cdn (not storage)

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

// s3RefAsset creates an asset representing an S3 bucket reference (e.g., from DNS or app config).
func s3RefAsset(id string, s3Ref map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"s3_ref": s3Ref,
		},
	}
}

// cdnAsset creates a CloudFront distribution asset.
func cdnAsset(id string, cdn map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_cloudfront_distribution"),
		Vendor: "aws",
		Properties: map[string]any{
			"cdn": cdn,
		},
	}
}

func takeoverSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadTakeoverControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.BUCKET.TAKEOVER.001": {},
		"CTL.S3.DANGLING.ORIGIN.001": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d takeover controls, found %d", len(ids), len(controls))
	}
	return controls
}

func takeoverEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadTakeoverControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasTakeoverFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoTakeoverFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- BUCKET.TAKEOVER.001: Referenced S3 Buckets Must Exist And Be Owned ---
// any: bucket_exists=false OR bucket_owned=false

func TestBucketTakeover001_TruePositive_BucketNotExist(t *testing.T) {
	ev := takeoverEvaluator(t)
	a := s3RefAsset("dangling-ref", map[string]any{
		"bucket_exists": false,
		"bucket_owned":  true,
	})

	result := ev.Evaluate(takeoverSnapshot(a))

	assertHasTakeoverFinding(t, result, "CTL.S3.BUCKET.TAKEOVER.001", "dangling-ref")
}

func TestBucketTakeover001_TruePositive_BucketNotOwned(t *testing.T) {
	ev := takeoverEvaluator(t)
	a := s3RefAsset("unowned-ref", map[string]any{
		"bucket_exists": true,
		"bucket_owned":  false,
	})

	result := ev.Evaluate(takeoverSnapshot(a))

	assertHasTakeoverFinding(t, result, "CTL.S3.BUCKET.TAKEOVER.001", "unowned-ref")
}

func TestBucketTakeover001_TrueNegative_BucketExistsAndOwned(t *testing.T) {
	ev := takeoverEvaluator(t)
	a := s3RefAsset("owned-ref", map[string]any{
		"bucket_exists": true,
		"bucket_owned":  true,
	})

	result := ev.Evaluate(takeoverSnapshot(a))

	assertNoTakeoverFinding(t, result, "CTL.S3.BUCKET.TAKEOVER.001", "owned-ref")
}

// --- DANGLING.ORIGIN.001: CDN S3 Origins Must Not Be Dangling ---
// Gated by: cdn.kind=distribution

func TestDanglingOrigin001_TruePositive_DanglingS3Origin(t *testing.T) {
	ev := takeoverEvaluator(t)
	a := cdnAsset("cf-dist-dangling", map[string]any{
		"kind":                    "distribution",
		"origins_has_dangling_s3": true,
	})

	result := ev.Evaluate(takeoverSnapshot(a))

	assertHasTakeoverFinding(t, result, "CTL.S3.DANGLING.ORIGIN.001", "cf-dist-dangling")
}

func TestDanglingOrigin001_TrueNegative_NoDanglingOrigin(t *testing.T) {
	ev := takeoverEvaluator(t)
	a := cdnAsset("cf-dist-safe", map[string]any{
		"kind":                    "distribution",
		"origins_has_dangling_s3": false,
	})

	result := ev.Evaluate(takeoverSnapshot(a))

	assertNoTakeoverFinding(t, result, "CTL.S3.DANGLING.ORIGIN.001", "cf-dist-safe")
}

func TestDanglingOrigin001_TrueNegative_NotADistribution(t *testing.T) {
	ev := takeoverEvaluator(t)
	// Not a distribution — control should not fire
	a := cdnAsset("not-dist", map[string]any{
		"kind":                    "function",
		"origins_has_dangling_s3": true,
	})

	result := ev.Evaluate(takeoverSnapshot(a))

	assertNoTakeoverFinding(t, result, "CTL.S3.DANGLING.ORIGIN.001", "not-dist")
}
