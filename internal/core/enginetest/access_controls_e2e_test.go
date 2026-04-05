package enginetest

// E2E tests for S3 Access controls (ACCESS.001-003, AUTH.READ/WRITE).
// Tests the full pipeline: observation fixture → built-in control YAML
// → predicate evaluation (inline and alias) → CEL engine → findings.
//
// Test matrix:
//   - True positive: unsafe access pattern → violation
//   - True negative: private/restricted bucket → no violation
//   - ACCESS.001 allowlist: external account in allowed_accounts → no violation

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

// accessBucket creates an S3 bucket with storage.kind="bucket" and the given access flags.
func accessBucket(id string, access map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": map[string]any{
				"kind":   "bucket",
				"access": access,
			},
		},
	}
}

// accessGrantsBucket creates an S3 bucket with storage.kind="bucket" and access_grants properties.
func accessGrantsBucket(id string, grants map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": map[string]any{
				"kind":          "bucket",
				"access_grants": grants,
			},
		},
	}
}

// accessBucketWithKind creates an S3 bucket with storage.kind="bucket" and access flags.
func accessBucketWithKind(id string, access map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": map[string]any{
				"kind":   "bucket",
				"access": access,
			},
		},
	}
}

func accessSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

// --- Control loader ---

func loadAccessControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.ACCESS.001":        {},
		"CTL.S3.ACCESS.002":        {},
		"CTL.S3.ACCESS.003":        {},
		"CTL.S3.ACCESS.GRANTS.001": {},
		"CTL.S3.ACCESS.GRANTS.002": {},
		"CTL.S3.PRESIGNED.001":     {},
		"CTL.S3.AUTH.READ.001":     {},
		"CTL.S3.AUTH.WRITE.001":    {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d access controls, found %d", len(ids), len(controls))
	}
	return controls
}

func accessEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadAccessControls(t),
		0, // 0h threshold — unsafe_state fires immediately
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

// --- E2E Tests: CTL.S3.ACCESS.001 (Cross-Account Access) ---

func TestAccess001_TruePositive_ExternalAccountAccess(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("xaccount-bucket", map[string]any{
		"external_account_ids": []any{"999888777666"},
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.001", "xaccount-bucket")
}

func TestAccess001_TrueNegative_NoExternalAccounts(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("private-bucket", map[string]any{
		"external_account_ids": []any{},
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.ACCESS.001", "private-bucket")
}

// --- E2E Tests: CTL.S3.ACCESS.002 (Wildcard Actions) ---

func TestAccess002_TruePositive_WildcardPolicy(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("wildcard-bucket", map[string]any{
		"has_wildcard_policy": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.002", "wildcard-bucket")
}

func TestAccess002_TrueNegative_SpecificActions(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("scoped-bucket", map[string]any{
		"has_wildcard_policy": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.ACCESS.002", "scoped-bucket")
}

// --- E2E Tests: CTL.S3.ACCESS.003 (External Write) ---

func TestAccess003_TruePositive_ExternalWriteAccess(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("writable-bucket", map[string]any{
		"has_external_write": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.003", "writable-bucket")
}

func TestAccess003_TrueNegative_ReadOnlyExternal(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("readonly-bucket", map[string]any{
		"has_external_write": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.ACCESS.003", "readonly-bucket")
}

// --- E2E Tests: CTL.S3.AUTH.READ.001 (Authenticated Read) ---

func TestAuthRead001_TruePositive(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("auth-read-bucket", map[string]any{
		"authenticated_read": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.AUTH.READ.001", "auth-read-bucket")
}

func TestAuthRead001_TrueNegative(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("safe-bucket", map[string]any{
		"authenticated_read": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.AUTH.READ.001", "safe-bucket")
}

// --- E2E Tests: CTL.S3.AUTH.WRITE.001 (Authenticated Write) ---

func TestAuthWrite001_TruePositive(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("auth-write-bucket", map[string]any{
		"authenticated_write": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.AUTH.WRITE.001", "auth-write-bucket")
}

func TestAuthWrite001_TrueNegative(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("safe-bucket", map[string]any{
		"authenticated_write": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.AUTH.WRITE.001", "safe-bucket")
}

// --- E2E Tests: CTL.S3.ACCESS.GRANTS.001 (Broad Write Grants) ---
// Gated by: kind=bucket AND access_grants.instance_exists=true
// Unsafe when: has_broad_write_grant=true

func TestAccessGrants001_TruePositive_BroadWriteGrant(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessGrantsBucket("broad-grant-bucket", map[string]any{
		"instance_exists":       true,
		"has_broad_write_grant": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.GRANTS.001", "broad-grant-bucket")
}

func TestAccessGrants001_TrueNegative_NoBroadWriteGrant(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessGrantsBucket("scoped-grant-bucket", map[string]any{
		"instance_exists":       true,
		"has_broad_write_grant": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.ACCESS.GRANTS.001", "scoped-grant-bucket")
}

func TestAccessGrants001_TrueNegative_NoGrantsInstance(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessGrantsBucket("no-grants-bucket", map[string]any{
		"instance_exists":       false,
		"has_broad_write_grant": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.ACCESS.GRANTS.001", "no-grants-bucket")
}

// --- E2E Tests: CTL.S3.ACCESS.GRANTS.002 (Identity Center Must Be Attached) ---
// Gated by: kind=bucket AND access_grants.instance_exists=true
// Unsafe when: identity_center_attached=false

func TestAccessGrants002_TruePositive_NoIdentityCenter(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessGrantsBucket("no-ic-bucket", map[string]any{
		"instance_exists":          true,
		"identity_center_attached": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.GRANTS.002", "no-ic-bucket")
}

func TestAccessGrants002_TrueNegative_IdentityCenterAttached(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessGrantsBucket("ic-bucket", map[string]any{
		"instance_exists":          true,
		"identity_center_attached": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.ACCESS.GRANTS.002", "ic-bucket")
}

func TestAccessGrants002_TrueNegative_NoGrantsInstance(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessGrantsBucket("no-grants-bucket-2", map[string]any{
		"instance_exists":          false,
		"identity_center_attached": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.ACCESS.GRANTS.002", "no-grants-bucket-2")
}

// --- E2E Tests: CTL.S3.PRESIGNED.001 (Presigned URL Access Must Be Restricted) ---
// Gated by: kind=bucket
// Unsafe when: presigned_url_restricted=false

func TestPresigned001_TruePositive_Unrestricted(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucketWithKind("unrestricted-presign-bucket", map[string]any{
		"presigned_url_restricted": false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.PRESIGNED.001", "unrestricted-presign-bucket")
}

func TestPresigned001_TrueNegative_Restricted(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucketWithKind("restricted-presign-bucket", map[string]any{
		"presigned_url_restricted": true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertNoAccessFinding(t, result, "CTL.S3.PRESIGNED.001", "restricted-presign-bucket")
}

// --- Cross-control: combined violations ---

func TestAccess_MultipleViolations_SameBucket(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("nightmare-bucket", map[string]any{
		"external_account_ids": []any{"999888777666"},
		"has_wildcard_policy":  true,
		"has_external_write":   true,
		"authenticated_read":   true,
		"authenticated_write":  true,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.001", "nightmare-bucket")
	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.002", "nightmare-bucket")
	assertHasAccessFinding(t, result, "CTL.S3.ACCESS.003", "nightmare-bucket")
	assertHasAccessFinding(t, result, "CTL.S3.AUTH.READ.001", "nightmare-bucket")
	assertHasAccessFinding(t, result, "CTL.S3.AUTH.WRITE.001", "nightmare-bucket")
}

func TestAccess_AllSafe(t *testing.T) {
	ev := accessEvaluator(t)
	bucket := accessBucket("safe-bucket", map[string]any{
		"external_account_ids": []any{},
		"has_wildcard_policy":  false,
		"has_external_write":   false,
		"authenticated_read":   false,
		"authenticated_write":  false,
	})

	result := ev.Evaluate(accessSnapshot(bucket))

	if result.Summary.Violations != 0 {
		t.Errorf("fully safe bucket should have 0 violations, got %d", result.Summary.Violations)
	}
}

// --- Assertion helpers (access-specific, reuse the same pattern) ---

func assertHasAccessFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoAccessFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}
