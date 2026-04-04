package enginetest

// E2E tests for CTL.S3.REPO.ARTIFACT.001 (Public Buckets Must Not Expose VCS Artifacts).
//
// This control has a compound predicate:
//   all:
//     - any: [public_read=true, public_list=true]
//     - exposed_repo_artifacts=true
//
// Both conditions must hold: the bucket must be publicly accessible AND
// have VCS artifacts present. Tests verify all four quadrants.

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

const controlRepoArtifact kernel.ControlID = "CTL.S3.REPO.ARTIFACT.001"

func artifactBucket(id string, access, content map[string]any) asset.Asset {
	storage := map[string]any{}
	if access != nil {
		storage["access"] = access
	}
	if content != nil {
		storage["content"] = content
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

func artifactSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadRepoArtifactControl(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	for _, ctl := range all {
		if ctl.ID == controlRepoArtifact {
			return []policy.ControlDefinition{ctl}
		}
	}
	t.Fatalf("control %s not found in embedded controls", controlRepoArtifact)
	return nil
}

func artifactEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadRepoArtifactControl(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

// --- True Positive: public + artifacts exposed ---

func TestRepoArtifact_TruePositive_PublicReadWithArtifacts(t *testing.T) {
	ev := artifactEvaluator(t)
	bucket := artifactBucket("website-bucket",
		map[string]any{"public_read": true},
		map[string]any{"exposed_repo_artifacts": true},
	)

	result := ev.Evaluate(artifactSnapshot(bucket))

	assertArtifactFinding(t, result, "website-bucket")
}

func TestRepoArtifact_TruePositive_PublicListWithArtifacts(t *testing.T) {
	ev := artifactEvaluator(t)
	bucket := artifactBucket("listing-bucket",
		map[string]any{"public_list": true},
		map[string]any{"exposed_repo_artifacts": true},
	)

	result := ev.Evaluate(artifactSnapshot(bucket))

	assertArtifactFinding(t, result, "listing-bucket")
}

// --- True Negative: only one condition met ---

func TestRepoArtifact_TrueNegative_PublicButNoArtifacts(t *testing.T) {
	ev := artifactEvaluator(t)
	bucket := artifactBucket("clean-public-bucket",
		map[string]any{"public_read": true},
		map[string]any{"exposed_repo_artifacts": false},
	)

	result := ev.Evaluate(artifactSnapshot(bucket))

	assertNoArtifactFinding(t, result, "clean-public-bucket")
}

func TestRepoArtifact_TrueNegative_ArtifactsPresentButPrivate(t *testing.T) {
	ev := artifactEvaluator(t)
	bucket := artifactBucket("private-with-git",
		map[string]any{"public_read": false, "public_list": false},
		map[string]any{"exposed_repo_artifacts": true},
	)

	result := ev.Evaluate(artifactSnapshot(bucket))

	assertNoArtifactFinding(t, result, "private-with-git")
}

func TestRepoArtifact_TrueNegative_FullyPrivate(t *testing.T) {
	ev := artifactEvaluator(t)
	bucket := artifactBucket("safe-bucket",
		map[string]any{"public_read": false, "public_list": false},
		map[string]any{"exposed_repo_artifacts": false},
	)

	result := ev.Evaluate(artifactSnapshot(bucket))

	assertNoArtifactFinding(t, result, "safe-bucket")
}

// --- Assertion helpers ---

func assertArtifactFinding(t *testing.T, result evaluation.Result, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlRepoArtifact && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlRepoArtifact, assetID, len(result.Findings))
}

func assertNoArtifactFinding(t *testing.T, result evaluation.Result, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlRepoArtifact && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlRepoArtifact, assetID)
			return
		}
	}
}
