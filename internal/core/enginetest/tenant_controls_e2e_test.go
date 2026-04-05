package enginetest

// E2E tests for CTL.S3.TENANT.ISOLATION.001.
// This control uses any_match on identities to detect app-signer identities
// that allow path traversal or disable prefix enforcement on shared buckets.
//
// Predicate:
//   all:
//     - storage.kind=bucket
//     - storage.tags.tenant_mode=shared
//     - storage.tags.tenant_prefix present
//     - identities any_match:
//         all:
//           - type=app_signer
//           - id contains "appsigner:s3:"
//           - any: [purpose contains "allow_traversal=true",
//                   purpose contains "enforce_prefix=false"]

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

func tenantBucket(id string, tags map[string]any) asset.Asset {
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

func tenantSnapshotWithIdentities(a asset.Asset, identities []asset.CloudIdentity) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: []asset.Asset{a}, Identities: identities},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: []asset.Asset{a}, Identities: identities},
	}
}

func loadTenantControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	for _, ctl := range all {
		if ctl.ID == "CTL.S3.TENANT.ISOLATION.001" {
			return []policy.ControlDefinition{ctl}
		}
	}
	t.Fatalf("control CTL.S3.TENANT.ISOLATION.001 not found")
	return nil
}

func tenantEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadTenantControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasTenantFinding(t *testing.T, result evaluation.Audit, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == "CTL.S3.TENANT.ISOLATION.001" && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding CTL.S3.TENANT.ISOLATION.001 for asset %s, got %d findings", assetID, len(result.Findings))
}

func assertNoTenantFinding(t *testing.T, result evaluation.Audit, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == "CTL.S3.TENANT.ISOLATION.001" && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding CTL.S3.TENANT.ISOLATION.001 for asset %s", assetID)
			return
		}
	}
}

func TestTenantIsolation001_TruePositive_TraversalEnabled(t *testing.T) {
	ev := tenantEvaluator(t)
	bucket := tenantBucket("shared-bucket", map[string]any{
		"tenant_mode":   "shared",
		"tenant_prefix": "org-123",
	})
	identities := []asset.CloudIdentity{
		{
			ID:     "appsigner:s3:uploads",
			Type:   kernel.NewAssetType("app_signer"),
			Vendor: "aws",
			Properties: map[string]any{
				"purpose": "enforce_prefix=true allow_traversal=true",
			},
		},
	}

	result := ev.Evaluate(tenantSnapshotWithIdentities(bucket, identities))

	assertHasTenantFinding(t, result, "shared-bucket")
}

func TestTenantIsolation001_TruePositive_PrefixEnforcementDisabled(t *testing.T) {
	ev := tenantEvaluator(t)
	bucket := tenantBucket("shared-bucket-2", map[string]any{
		"tenant_mode":   "shared",
		"tenant_prefix": "org-456",
	})
	identities := []asset.CloudIdentity{
		{
			ID:     "appsigner:s3:downloads",
			Type:   kernel.NewAssetType("app_signer"),
			Vendor: "aws",
			Properties: map[string]any{
				"purpose": "enforce_prefix=false allow_traversal=false",
			},
		},
	}

	result := ev.Evaluate(tenantSnapshotWithIdentities(bucket, identities))

	assertHasTenantFinding(t, result, "shared-bucket-2")
}

func TestTenantIsolation001_TrueNegative_PrefixEnforcedNoTraversal(t *testing.T) {
	ev := tenantEvaluator(t)
	bucket := tenantBucket("safe-shared-bucket", map[string]any{
		"tenant_mode":   "shared",
		"tenant_prefix": "org-789",
	})
	identities := []asset.CloudIdentity{
		{
			ID:     "appsigner:s3:uploads",
			Type:   kernel.NewAssetType("app_signer"),
			Vendor: "aws",
			Properties: map[string]any{
				"purpose": "enforce_prefix=true allow_traversal=false",
			},
		},
	}

	result := ev.Evaluate(tenantSnapshotWithIdentities(bucket, identities))

	assertNoTenantFinding(t, result, "safe-shared-bucket")
}

func TestTenantIsolation001_TrueNegative_NotSharedBucket(t *testing.T) {
	ev := tenantEvaluator(t)
	// Not a shared bucket — control should not fire
	bucket := tenantBucket("single-tenant-bucket", map[string]any{
		"tenant_mode":   "single",
		"tenant_prefix": "org-100",
	})
	identities := []asset.CloudIdentity{
		{
			ID:     "appsigner:s3:uploads",
			Type:   kernel.NewAssetType("app_signer"),
			Vendor: "aws",
			Properties: map[string]any{
				"purpose": "enforce_prefix=false allow_traversal=true",
			},
		},
	}

	result := ev.Evaluate(tenantSnapshotWithIdentities(bucket, identities))

	assertNoTenantFinding(t, result, "single-tenant-bucket")
}

func TestTenantIsolation001_TrueNegative_NoIdentities(t *testing.T) {
	ev := tenantEvaluator(t)
	bucket := tenantBucket("no-id-bucket", map[string]any{
		"tenant_mode":   "shared",
		"tenant_prefix": "org-200",
	})

	result := ev.Evaluate(tenantSnapshotWithIdentities(bucket, nil))

	assertNoTenantFinding(t, result, "no-id-bucket")
}
