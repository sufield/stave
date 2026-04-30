package enginetest

// E2E tests for S3 Network controls.
//   - NETWORK.001: effective_network_scope=public → violation (no kind gate)
//   - NETWORK.VPC.001: kind=bucket AND has_vpc_condition=false AND has_ip_condition=false → violation
//   - NETWORK.POLICY.001: vpc_endpoint_policy.attached=false OR is_default_full_access=true → violation
//   - MRAP.PAB.001: kind=bucket AND mrap_public_access_blocked=false → violation
//   - MRAP.POLICY.001: kind=bucket AND mrap_policy_is_public=true → violation
//   - AP.PAB.001: kind=access_point AND public_access_fully_blocked=false → violation
//   - AP.POLICY.001: kind=access_point AND policy_is_public=true → violation

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

func networkBucket(id string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": props,
		},
	}
}

func networkSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadNetworkControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.NETWORK.001":        {},
		"CTL.S3.NETWORK.VPC.001":    {},
		"CTL.S3.NETWORK.POLICY.001": {},
		"CTL.S3.MRAP.PAB.001":       {},
		"CTL.S3.MRAP.POLICY.001":    {},
		"CTL.S3.AP.PAB.001":         {},
		"CTL.S3.AP.POLICY.001":      {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d network controls, found %d", len(ids), len(controls))
	}
	return controls
}

func networkEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadNetworkControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasNetworkFinding(t *testing.T, result *evaluation.ComplianceReport, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoNetworkFinding(t *testing.T, result *evaluation.ComplianceReport, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- NETWORK.001: Public-Principal Policies Must Have Network Conditions ---
// access.effective_network_scope=public (no kind gate)

func TestNetwork001_TruePositive_PublicNetworkScope(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("public-net-bucket", map[string]any{
		"access": map[string]any{
			"effective_network_scope": "public",
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertHasNetworkFinding(t, &result, "CTL.S3.NETWORK.001", "public-net-bucket")
}

func TestNetwork001_TrueNegative_VPCScope(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("vpc-bucket", map[string]any{
		"access": map[string]any{
			"effective_network_scope": "vpc",
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertNoNetworkFinding(t, &result, "CTL.S3.NETWORK.001", "vpc-bucket")
}

// --- NETWORK.VPC.001: VPC Endpoint or IP Condition Required ---
// kind=bucket AND has_vpc_condition=false AND has_ip_condition=false

func TestNetworkVPC001_TruePositive_NoNetworkConditions(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("no-net-cond-bucket", map[string]any{
		"kind": "bucket",
		"access": map[string]any{
			"has_vpc_condition": false,
			"has_ip_condition":  false,
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertHasNetworkFinding(t, &result, "CTL.S3.NETWORK.VPC.001", "no-net-cond-bucket")
}

func TestNetworkVPC001_TrueNegative_HasVPCCondition(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("vpc-cond-bucket", map[string]any{
		"kind": "bucket",
		"access": map[string]any{
			"has_vpc_condition": true,
			"has_ip_condition":  false,
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertNoNetworkFinding(t, &result, "CTL.S3.NETWORK.VPC.001", "vpc-cond-bucket")
}

func TestNetworkVPC001_TrueNegative_HasIPCondition(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("ip-cond-bucket", map[string]any{
		"kind": "bucket",
		"access": map[string]any{
			"has_vpc_condition": false,
			"has_ip_condition":  true,
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertNoNetworkFinding(t, &result, "CTL.S3.NETWORK.VPC.001", "ip-cond-bucket")
}

// --- NETWORK.POLICY.001: VPC Endpoint Policy Must Restrict Access ---
// any: attached=false OR is_default_full_access=true

func TestNetworkPolicy001_TruePositive_PolicyNotAttached(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("no-policy-bucket", map[string]any{
		"network": map[string]any{
			"vpc_endpoint_policy": map[string]any{
				"attached":               false,
				"is_default_full_access": false,
			},
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertHasNetworkFinding(t, &result, "CTL.S3.NETWORK.POLICY.001", "no-policy-bucket")
}

func TestNetworkPolicy001_TruePositive_DefaultFullAccess(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("default-policy-bucket", map[string]any{
		"network": map[string]any{
			"vpc_endpoint_policy": map[string]any{
				"attached":               true,
				"is_default_full_access": true,
			},
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertHasNetworkFinding(t, &result, "CTL.S3.NETWORK.POLICY.001", "default-policy-bucket")
}

func TestNetworkPolicy001_TrueNegative_RestrictivePolicy(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("restricted-policy-bucket", map[string]any{
		"network": map[string]any{
			"vpc_endpoint_policy": map[string]any{
				"attached":               true,
				"is_default_full_access": false,
			},
		},
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertNoNetworkFinding(t, &result, "CTL.S3.NETWORK.POLICY.001", "restricted-policy-bucket")
}

// --- MRAP.PAB.001: MRAP Must Have Block Public Access ---
// kind=bucket AND mrap_public_access_blocked=false

func TestMRAPPAB001_TruePositive_PABDisabled(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("mrap-no-pab-bucket", map[string]any{
		"kind":                       "bucket",
		"mrap_public_access_blocked": false,
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertHasNetworkFinding(t, &result, "CTL.S3.MRAP.PAB.001", "mrap-no-pab-bucket")
}

func TestMRAPPAB001_TrueNegative_PABEnabled(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("mrap-pab-bucket", map[string]any{
		"kind":                       "bucket",
		"mrap_public_access_blocked": true,
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertNoNetworkFinding(t, &result, "CTL.S3.MRAP.PAB.001", "mrap-pab-bucket")
}

// --- MRAP.POLICY.001: MRAP Policy Must Not Be Public ---
// kind=bucket AND mrap_policy_is_public=true

func TestMRAPPolicy001_TruePositive_PublicPolicy(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("mrap-public-bucket", map[string]any{
		"kind":                  "bucket",
		"mrap_policy_is_public": true,
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertHasNetworkFinding(t, &result, "CTL.S3.MRAP.POLICY.001", "mrap-public-bucket")
}

func TestMRAPPolicy001_TrueNegative_PrivatePolicy(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	bucket := networkBucket("mrap-private-bucket", map[string]any{
		"kind":                  "bucket",
		"mrap_policy_is_public": false,
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertNoNetworkFinding(t, &result, "CTL.S3.MRAP.POLICY.001", "mrap-private-bucket")
}

// --- AP.PAB.001: Access Point Must Have Block Public Access ---
// kind=access_point AND public_access_fully_blocked=false

// accessPoint builds an aws_s3_access_point asset. Access Points are their own
// resource kind distinct from buckets — discriminator is storage.kind="access_point".
func accessPoint(id string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_access_point"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": props,
		},
	}
}

func TestAPPAB001_TruePositive_PABDisabled(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	ap := accessPoint("ap-no-pab", map[string]any{
		"kind":                        "access_point",
		"public_access_fully_blocked": false,
	})

	result := ev.Evaluate(networkSnapshot(ap))

	assertHasNetworkFinding(t, &result, "CTL.S3.AP.PAB.001", "ap-no-pab")
}

func TestAPPAB001_TrueNegative_PABEnabled(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	ap := accessPoint("ap-with-pab", map[string]any{
		"kind":                        "access_point",
		"public_access_fully_blocked": true,
	})

	result := ev.Evaluate(networkSnapshot(ap))

	assertNoNetworkFinding(t, &result, "CTL.S3.AP.PAB.001", "ap-with-pab")
}

func TestAPPAB001_TrueNegative_BucketKindIgnored(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	// A bucket observation with the same public_access_fully_blocked=false must
	// not trip AP.PAB.001 — it's gated on kind=access_point.
	bucket := networkBucket("plain-bucket", map[string]any{
		"kind":                        "bucket",
		"public_access_fully_blocked": false,
	})

	result := ev.Evaluate(networkSnapshot(bucket))

	assertNoNetworkFinding(t, &result, "CTL.S3.AP.PAB.001", "plain-bucket")
}

// --- AP.POLICY.001: Access Point Policy Must Not Be Public ---
// kind=access_point AND policy_is_public=true

func TestAPPolicy001_TruePositive_PublicPolicy(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	ap := accessPoint("ap-public-policy", map[string]any{
		"kind":             "access_point",
		"policy_is_public": true,
	})

	result := ev.Evaluate(networkSnapshot(ap))

	assertHasNetworkFinding(t, &result, "CTL.S3.AP.POLICY.001", "ap-public-policy")
}

func TestAPPolicy001_TrueNegative_ScopedPolicy(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	ap := accessPoint("ap-scoped-policy", map[string]any{
		"kind":             "access_point",
		"policy_is_public": false,
	})

	result := ev.Evaluate(networkSnapshot(ap))

	assertNoNetworkFinding(t, &result, "CTL.S3.AP.POLICY.001", "ap-scoped-policy")
}

func TestAPPolicy001_TrueNegative_VPCOriginNarrowPolicy(t *testing.T) {
	t.Parallel()
	ev := networkEvaluator(t)
	// Full AP shape: VPC-bound network origin, PAB fully enforcing, non-public
	// policy. Silent on both AP.POLICY.001 and AP.PAB.001.
	ap := accessPoint("ap-vpc-only", map[string]any{
		"kind":                        "access_point",
		"name":                        "internal-ap",
		"bucket_name":                 "data-bucket",
		"network_origin":              "vpc",
		"vpc_id":                      "vpc-abc123",
		"alias":                       "internal-ap-xxxx.s3-accesspoint.us-east-1.amazonaws.com",
		"policy_is_public":            false,
		"public_access_fully_blocked": true,
		"public_access_block": map[string]any{
			"block_public_acls":       true,
			"ignore_public_acls":      true,
			"block_public_policy":     true,
			"restrict_public_buckets": true,
		},
	})

	result := ev.Evaluate(networkSnapshot(ap))

	assertNoNetworkFinding(t, &result, "CTL.S3.AP.POLICY.001", "ap-vpc-only")
	assertNoNetworkFinding(t, &result, "CTL.S3.AP.PAB.001", "ap-vpc-only")
}
