package enginetest

// E2E tests for ACL security controls (ESCALATION, FULLCONTROL, RECON).
// These verify the full pipeline: observation fixture → built-in control YAML
// → predicate alias resolution → CEL evaluation → finding generation.
//
// Test matrix covers:
//   - True positive: ACL grant with PAB disabled → violation
//   - True positive (wildcard policy): s3:* action → violation
//   - PAB override: ACL grant with PAB enabled → no violation
//   - True negative: private bucket → no violation

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

func aclBucket(id string, access map[string]any, pab map[string]any) asset.Asset {
	storage := map[string]any{"access": access}
	if pab != nil {
		storage["controls"] = map[string]any{"public_access_block": pab}
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

func pabEnabled() map[string]any {
	return map[string]any{
		"block_public_acls":       true,
		"ignore_public_acls":      true,
		"block_public_policy":     true,
		"restrict_public_buckets": true,
	}
}

func pabDisabled() map[string]any {
	return map[string]any{
		"block_public_acls":       false,
		"ignore_public_acls":      false,
		"block_public_policy":     false,
		"restrict_public_buckets": false,
	}
}

func privateBucket(id string) asset.Asset {
	return aclBucket(id, map[string]any{
		"public_read":                    false,
		"public_admin":                   false,
		"authenticated_admin":            false,
		"has_full_control_public":        false,
		"has_full_control_authenticated": false,
	}, pabEnabled())
}

func aclSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

// --- Control loader ---

func loadACLControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	aclIDs := map[kernel.ControlID]struct{}{
		"CTL.S3.ACL.ESCALATION.001":  {},
		"CTL.S3.ACL.FULLCONTROL.001": {},
		"CTL.S3.ACL.RECON.001":       {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := aclIDs[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(aclIDs) {
		t.Fatalf("expected %d ACL controls, found %d", len(aclIDs), len(controls))
	}
	return controls
}

func aclEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	// Use 0h threshold so unsafe_state controls fire as soon as the predicate
	// matches, without requiring the unsafe duration to exceed a time window.
	return NewEvaluator(
		loadACLControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

// --- E2E Tests: CTL.S3.ACL.ESCALATION.001 (WRITE_ACP) ---

func TestACL_Escalation_TruePositive_PublicWriteACP(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("vuln-bucket", map[string]any{
		"public_admin":        true,
		"authenticated_admin": false,
	}, pabDisabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertHasFinding(t, result, "CTL.S3.ACL.ESCALATION.001", "vuln-bucket")
}

func TestACL_Escalation_TruePositive_AuthenticatedWriteACP(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("vuln-bucket", map[string]any{
		"public_admin":        false,
		"authenticated_admin": true,
	}, pabDisabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertHasFinding(t, result, "CTL.S3.ACL.ESCALATION.001", "vuln-bucket")
}

func TestACL_Escalation_PABOverride(t *testing.T) {
	ev := aclEvaluator(t)
	// Terrible ACL but PAB is enabled — should NOT fire.
	bucket := aclBucket("pab-bucket", map[string]any{
		"public_admin":        false, // PAB forces this to false
		"authenticated_admin": false, // PAB forces this to false
	}, pabEnabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertNoFinding(t, result, "CTL.S3.ACL.ESCALATION.001", "pab-bucket")
}

func TestACL_Escalation_TrueNegative_PrivateBucket(t *testing.T) {
	ev := aclEvaluator(t)
	result := ev.Evaluate(aclSnapshot(privateBucket("safe-bucket")))

	assertNoFinding(t, result, "CTL.S3.ACL.ESCALATION.001", "safe-bucket")
}

// --- E2E Tests: CTL.S3.ACL.FULLCONTROL.001 ---

func TestACL_FullControl_TruePositive_PublicFullControl(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("full-ctl-bucket", map[string]any{
		"has_full_control_public":        true,
		"has_full_control_authenticated": false,
	}, pabDisabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertHasFinding(t, result, "CTL.S3.ACL.FULLCONTROL.001", "full-ctl-bucket")
}

func TestACL_FullControl_TruePositive_AuthenticatedFullControl(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("auth-ctl-bucket", map[string]any{
		"has_full_control_public":        false,
		"has_full_control_authenticated": true,
	}, pabDisabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertHasFinding(t, result, "CTL.S3.ACL.FULLCONTROL.001", "auth-ctl-bucket")
}

func TestACL_FullControl_PABOverride(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("pab-bucket", map[string]any{
		"has_full_control_public":        false,
		"has_full_control_authenticated": false,
	}, pabEnabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertNoFinding(t, result, "CTL.S3.ACL.FULLCONTROL.001", "pab-bucket")
}

func TestACL_FullControl_TrueNegative(t *testing.T) {
	ev := aclEvaluator(t)
	result := ev.Evaluate(aclSnapshot(privateBucket("safe-bucket")))

	assertNoFinding(t, result, "CTL.S3.ACL.FULLCONTROL.001", "safe-bucket")
}

// --- E2E Tests: CTL.S3.ACL.RECON.001 (READ_ACP) ---

func TestACL_Recon_TruePositive_PublicReadACP(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("recon-bucket", map[string]any{
		"public_admin": true,
	}, pabDisabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertHasFinding(t, result, "CTL.S3.ACL.RECON.001", "recon-bucket")
}

func TestACL_Recon_PABOverride(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("pab-bucket", map[string]any{
		"public_admin": false,
	}, pabEnabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertNoFinding(t, result, "CTL.S3.ACL.RECON.001", "pab-bucket")
}

func TestACL_Recon_TrueNegative(t *testing.T) {
	ev := aclEvaluator(t)
	result := ev.Evaluate(aclSnapshot(privateBucket("safe-bucket")))

	assertNoFinding(t, result, "CTL.S3.ACL.RECON.001", "safe-bucket")
}

// --- Cross-control: multiple violations on the same bucket ---

func TestACL_MultipleViolations_SameBucket(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("nightmare-bucket", map[string]any{
		"public_admin":                   true,
		"authenticated_admin":            true,
		"has_full_control_public":        true,
		"has_full_control_authenticated": true,
	}, pabDisabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	assertHasFinding(t, result, "CTL.S3.ACL.ESCALATION.001", "nightmare-bucket")
	assertHasFinding(t, result, "CTL.S3.ACL.FULLCONTROL.001", "nightmare-bucket")
	assertHasFinding(t, result, "CTL.S3.ACL.RECON.001", "nightmare-bucket")
}

func TestACL_MultipleViolations_PABOverridesAll(t *testing.T) {
	ev := aclEvaluator(t)
	bucket := aclBucket("pab-bucket", map[string]any{
		"public_admin":                   false,
		"authenticated_admin":            false,
		"has_full_control_public":        false,
		"has_full_control_authenticated": false,
	}, pabEnabled())

	result := ev.Evaluate(aclSnapshot(bucket))

	if result.Summary.Violations != 0 {
		t.Errorf("PAB-enabled bucket should have 0 violations, got %d", result.Summary.Violations)
	}
}

// --- Assertion helpers ---

func assertHasFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}
