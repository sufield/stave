package enginetest

// E2E tests for S3 Public exposure controls (15 controls in public/).
//
// Controls tested:
//   - PUBLIC.001: public_read=true (any:, no kind gate)
//   - PUBLIC.002: (public_read OR public_list) AND data-classification in [phi,pii,confidential]
//   - PUBLIC.003: public_write=true (any:, no kind gate)
//   - PUBLIC.004: read_via_resource=true (unsafe_duration, max_unsafe_duration=0h)
//   - PUBLIC.005: latent_public_read (alias: s3.latent_public_read)
//   - PUBLIC.006: kind=bucket AND latent_public_list=true
//   - PUBLIC.007: read_via_identity=true (any:)
//   - PUBLIC.008: list_via_identity=true (any:)
//   - PUBLIC.LIST.001: public_list=true (any:)
//   - PUBLIC.LIST.002: kind=bucket AND public_list=true AND (public_list_intended missing OR != "true")
//   - PUBLIC.PREFIX.001: type=prefix_exposure — skipped (separate evaluation path)
//   - WEBSITE.PUBLIC.001: website.enabled=true AND public_read=true
//   - CDN.OAC.001: kind=bucket AND cdn_access.cloudfront_oai.enabled=true
//   - CDN.EXPOSURE.001: kind=bucket AND public_access_fully_blocked=true AND cdn_access.bucket_policy_grants_cloudfront=true
//   - ACL.WRITE.001: write_via_resource=true (any:)

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

func publicBucket(id string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": props,
		},
	}
}

func publicSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

// --- Control loader ---
// Load all public controls except PUBLIC.PREFIX.001 (prefix_exposure type uses separate evaluator).

func loadPublicControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.PUBLIC.001":         {},
		"CTL.S3.PUBLIC.002":         {},
		"CTL.S3.PUBLIC.003":         {},
		"CTL.S3.PUBLIC.004":         {},
		"CTL.S3.PUBLIC.005":         {},
		"CTL.S3.PUBLIC.006":         {},
		"CTL.S3.PUBLIC.007":         {},
		"CTL.S3.PUBLIC.008":         {},
		"CTL.S3.PUBLIC.LIST.001":    {},
		"CTL.S3.PUBLIC.LIST.002":    {},
		"CTL.S3.WEBSITE.PUBLIC.001": {},
		"CTL.S3.CDN.OAC.001":        {},
		"CTL.S3.CDN.EXPOSURE.001":   {},
		"CTL.S3.ACL.WRITE.001":      {},
		// PUBLIC.PREFIX.001 excluded: type=prefix_exposure uses separate evaluation path
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d public controls, found %d", len(ids), len(controls))
	}
	return controls
}

func publicEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadPublicControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

// --- Assertion helpers ---

func assertHasPublicFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoPublicFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// ===== PUBLIC.001: No Public S3 Bucket Read =====
// any: public_read=true

func TestPublic001_TruePositive_PublicRead(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("public-read-bucket", map[string]any{
		"access": map[string]any{"public_read": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.001", "public-read-bucket")
}

func TestPublic001_TrueNegative_PrivateRead(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("private-bucket", map[string]any{
		"access": map[string]any{"public_read": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.001", "private-bucket")
}

// ===== PUBLIC.002: No Public Sensitive Data =====
// all: (public_read OR public_list) AND data-classification in [phi, pii, confidential]

func TestPublic002_TruePositive_PublicReadPHI(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("phi-public-bucket", map[string]any{
		"access": map[string]any{"public_read": true, "public_list": false},
		"tags":   map[string]any{"data-classification": "phi"},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.002", "phi-public-bucket")
}

func TestPublic002_TruePositive_PublicListPII(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("pii-list-bucket", map[string]any{
		"access": map[string]any{"public_read": false, "public_list": true},
		"tags":   map[string]any{"data-classification": "pii"},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.002", "pii-list-bucket")
}

func TestPublic002_TrueNegative_PublicReadButPublicClassification(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("public-class-bucket", map[string]any{
		"access": map[string]any{"public_read": true},
		"tags":   map[string]any{"data-classification": "public"},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.002", "public-class-bucket")
}

func TestPublic002_TrueNegative_PrivatePHI(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("private-phi-bucket", map[string]any{
		"access": map[string]any{"public_read": false, "public_list": false},
		"tags":   map[string]any{"data-classification": "phi"},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.002", "private-phi-bucket")
}

// ===== PUBLIC.003: No Public Write =====
// any: public_write=true

func TestPublic003_TruePositive_PublicWrite(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("public-write-bucket", map[string]any{
		"access": map[string]any{"public_write": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.003", "public-write-bucket")
}

func TestPublic003_TrueNegative_NoPublicWrite(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-write-bucket", map[string]any{
		"access": map[string]any{"public_write": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.003", "no-write-bucket")
}

// ===== PUBLIC.004: No Public Read via ACL =====
// type: unsafe_duration (max_unsafe_duration=0h)
// any: read_via_resource=true

func TestPublic004_TruePositive_ReadViaResource(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("acl-read-bucket", map[string]any{
		"access": map[string]any{"read_via_resource": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.004", "acl-read-bucket")
}

func TestPublic004_TrueNegative_NoReadViaResource(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-acl-read-bucket", map[string]any{
		"access": map[string]any{"read_via_resource": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.004", "no-acl-read-bucket")
}

// ===== PUBLIC.005: No Latent Public Read Exposure =====
// Uses alias: s3.latent_public_read → latent_public_read=true

func TestPublic005_TruePositive_LatentPublicRead(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("latent-read-bucket", map[string]any{
		"access": map[string]any{"latent_public_read": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.005", "latent-read-bucket")
}

func TestPublic005_TrueNegative_NoLatentPublicRead(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-latent-bucket", map[string]any{
		"access": map[string]any{"latent_public_read": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.005", "no-latent-bucket")
}

// ===== PUBLIC.006: No Latent Public Bucket Listing =====
// kind=bucket AND latent_public_list=true

func TestPublic006_TruePositive_LatentPublicList(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("latent-list-bucket", map[string]any{
		"kind":   "bucket",
		"access": map[string]any{"latent_public_list": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.006", "latent-list-bucket")
}

func TestPublic006_TrueNegative_NoLatentPublicList(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-latent-list-bucket", map[string]any{
		"kind":   "bucket",
		"access": map[string]any{"latent_public_list": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.006", "no-latent-list-bucket")
}

// ===== PUBLIC.007: No Public Read via Policy =====
// any: read_via_identity=true

func TestPublic007_TruePositive_ReadViaIdentity(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("policy-read-bucket", map[string]any{
		"access": map[string]any{"read_via_identity": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.007", "policy-read-bucket")
}

func TestPublic007_TrueNegative_NoReadViaIdentity(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-policy-read-bucket", map[string]any{
		"access": map[string]any{"read_via_identity": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.007", "no-policy-read-bucket")
}

// ===== PUBLIC.008: No Public List via Policy =====
// any: list_via_identity=true

func TestPublic008_TruePositive_ListViaIdentity(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("policy-list-bucket", map[string]any{
		"access": map[string]any{"list_via_identity": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.008", "policy-list-bucket")
}

func TestPublic008_TrueNegative_NoListViaIdentity(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-policy-list-bucket", map[string]any{
		"access": map[string]any{"list_via_identity": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.008", "no-policy-list-bucket")
}

// ===== PUBLIC.LIST.001: No Public S3 Bucket Listing =====
// any: public_list=true

func TestPublicList001_TruePositive_PublicList(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("public-list-bucket", map[string]any{
		"access": map[string]any{"public_list": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.LIST.001", "public-list-bucket")
}

func TestPublicList001_TrueNegative_NoPublicList(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("private-list-bucket", map[string]any{
		"access": map[string]any{"public_list": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.LIST.001", "private-list-bucket")
}

// ===== PUBLIC.LIST.002: Anonymous Listing Must Be Explicitly Intended =====
// kind=bucket AND public_list=true AND (public_list_intended missing OR != "true")

func TestPublicList002_TruePositive_PublicListNoIntentTag(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("unintended-list-bucket", map[string]any{
		"kind":   "bucket",
		"access": map[string]any{"public_list": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.PUBLIC.LIST.002", "unintended-list-bucket")
}

func TestPublicList002_TrueNegative_PublicListWithIntentTag(t *testing.T) {
	ev := publicEvaluator(t)
	// YAML parses value: "true" as boolean true, so the tag must also be bool true.
	bucket := publicBucket("intended-list-bucket", map[string]any{
		"kind":   "bucket",
		"access": map[string]any{"public_list": true},
		"tags":   map[string]any{"public_list_intended": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.LIST.002", "intended-list-bucket")
}

func TestPublicList002_TrueNegative_NotPublicList(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("private-bucket-2", map[string]any{
		"kind":   "bucket",
		"access": map[string]any{"public_list": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.PUBLIC.LIST.002", "private-bucket-2")
}

// ===== WEBSITE.PUBLIC.001: No Public Website Hosting with Public Read =====
// website.enabled=true AND access.public_read=true

func TestWebsitePublic001_TruePositive_WebsiteWithPublicRead(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("website-bucket", map[string]any{
		"website": map[string]any{"enabled": true},
		"access":  map[string]any{"public_read": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.WEBSITE.PUBLIC.001", "website-bucket")
}

func TestWebsitePublic001_TrueNegative_WebsiteWithoutPublicRead(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("website-private-bucket", map[string]any{
		"website": map[string]any{"enabled": true},
		"access":  map[string]any{"public_read": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.WEBSITE.PUBLIC.001", "website-private-bucket")
}

func TestWebsitePublic001_TrueNegative_NoWebsiteHosting(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-website-bucket", map[string]any{
		"website": map[string]any{"enabled": false},
		"access":  map[string]any{"public_read": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.WEBSITE.PUBLIC.001", "no-website-bucket")
}

// ===== CDN.OAC.001: CloudFront Access Must Use OAC Not Legacy OAI =====
// kind=bucket AND cdn_access.cloudfront_oai.enabled=true

func TestCDNOAC001_TruePositive_LegacyOAI(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("oai-bucket", map[string]any{
		"kind": "bucket",
		"cdn_access": map[string]any{
			"cloudfront_oai": map[string]any{"enabled": true},
		},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.CDN.OAC.001", "oai-bucket")
}

func TestCDNOAC001_TrueNegative_UsingOAC(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("oac-bucket", map[string]any{
		"kind": "bucket",
		"cdn_access": map[string]any{
			"cloudfront_oai": map[string]any{"enabled": false},
			"cloudfront_oac": map[string]any{"enabled": true},
		},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.CDN.OAC.001", "oac-bucket")
}

// ===== CDN.EXPOSURE.001: Private Bucket Must Not Be Publicly Exposed Via CloudFront =====
// kind=bucket AND controls.public_access_fully_blocked=true AND cdn_access.bucket_policy_grants_cloudfront=true

func TestCDNExposure001_TruePositive_PABEnabledWithCFGrant(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("cdn-exposed-bucket", map[string]any{
		"kind": "bucket",
		"controls": map[string]any{
			"public_access_fully_blocked": true,
		},
		"cdn_access": map[string]any{
			"bucket_policy_grants_cloudfront": true,
		},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.CDN.EXPOSURE.001", "cdn-exposed-bucket")
}

func TestCDNExposure001_TrueNegative_PABEnabledNoCFGrant(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-cdn-bucket", map[string]any{
		"kind": "bucket",
		"controls": map[string]any{
			"public_access_fully_blocked": true,
		},
		"cdn_access": map[string]any{
			"bucket_policy_grants_cloudfront": false,
		},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.CDN.EXPOSURE.001", "no-cdn-bucket")
}

func TestCDNExposure001_TrueNegative_PABDisabledWithCFGrant(t *testing.T) {
	ev := publicEvaluator(t)
	// PAB is disabled — this control specifically targets the false sense of security
	// when PAB is enabled but CF creates a public path anyway
	bucket := publicBucket("pab-off-bucket", map[string]any{
		"kind": "bucket",
		"controls": map[string]any{
			"public_access_fully_blocked": false,
		},
		"cdn_access": map[string]any{
			"bucket_policy_grants_cloudfront": true,
		},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.CDN.EXPOSURE.001", "pab-off-bucket")
}

// ===== ACL.WRITE.001: No Public Write via ACL =====
// any: write_via_resource=true

func TestACLWrite001_TruePositive_WriteViaResource(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("acl-write-bucket", map[string]any{
		"access": map[string]any{"write_via_resource": true},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertHasPublicFinding(t, result, "CTL.S3.ACL.WRITE.001", "acl-write-bucket")
}

func TestACLWrite001_TrueNegative_NoWriteViaResource(t *testing.T) {
	ev := publicEvaluator(t)
	bucket := publicBucket("no-acl-write-bucket", map[string]any{
		"access": map[string]any{"write_via_resource": false},
	})

	result := ev.Evaluate(publicSnapshot(bucket))

	assertNoPublicFinding(t, result, "CTL.S3.ACL.WRITE.001", "no-acl-write-bucket")
}
