package enginetest

// E2E tests for S3 Write Scope controls (WRITE.SCOPE.001, WRITE.CONTENT.001).
// These controls check assets of type s3_upload_policy (not s3_bucket).
//
//   - WRITE.SCOPE.001: type=s3_upload_policy AND operation=write AND allowed_key_mode=prefix → violation
//   - WRITE.CONTENT.001: type=s3_upload_policy AND operation=write AND content_type_restricted=false → violation
//
// The `field: type` in the predicate resolves to the asset's Type field (via Map()).

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

func uploadPolicyAsset(id string, upload map[string]any) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("s3_upload_policy"),
		Vendor: "aws",
		Properties: map[string]any{
			"s3_upload": upload,
		},
	}
}

func writeScopeSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadWriteScopeControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.WRITE.SCOPE.001":   {},
		"CTL.S3.WRITE.CONTENT.001": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d write scope controls, found %d", len(ids), len(controls))
	}
	return controls
}

func writeScopeEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadWriteScopeControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasWriteScopeFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoWriteScopeFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- WRITE.SCOPE.001: Signed Upload Must Bind To Exact Object Key ---
// type=s3_upload_policy AND operation=write AND allowed_key_mode=prefix

func TestWriteScope001_TruePositive_PrefixKeyMode(t *testing.T) {
	ev := writeScopeEvaluator(t)
	a := uploadPolicyAsset("prefix-policy", map[string]any{
		"operation":        "write",
		"allowed_key_mode": "prefix",
	})

	result := ev.Evaluate(writeScopeSnapshot(a))

	assertHasWriteScopeFinding(t, result, "CTL.S3.WRITE.SCOPE.001", "prefix-policy")
}

func TestWriteScope001_TrueNegative_ExactKeyMode(t *testing.T) {
	ev := writeScopeEvaluator(t)
	a := uploadPolicyAsset("exact-policy", map[string]any{
		"operation":        "write",
		"allowed_key_mode": "exact",
	})

	result := ev.Evaluate(writeScopeSnapshot(a))

	assertNoWriteScopeFinding(t, result, "CTL.S3.WRITE.SCOPE.001", "exact-policy")
}

func TestWriteScope001_TrueNegative_ReadOperation(t *testing.T) {
	ev := writeScopeEvaluator(t)
	// Not a write operation — control should not fire
	a := uploadPolicyAsset("read-policy", map[string]any{
		"operation":        "read",
		"allowed_key_mode": "prefix",
	})

	result := ev.Evaluate(writeScopeSnapshot(a))

	assertNoWriteScopeFinding(t, result, "CTL.S3.WRITE.SCOPE.001", "read-policy")
}

// --- WRITE.CONTENT.001: Signed Upload Must Restrict Content Types ---
// type=s3_upload_policy AND operation=write AND content_type_restricted=false

func TestWriteContent001_TruePositive_UnrestrictedContentType(t *testing.T) {
	ev := writeScopeEvaluator(t)
	a := uploadPolicyAsset("unrestricted-policy", map[string]any{
		"operation":               "write",
		"content_type_restricted": false,
	})

	result := ev.Evaluate(writeScopeSnapshot(a))

	assertHasWriteScopeFinding(t, result, "CTL.S3.WRITE.CONTENT.001", "unrestricted-policy")
}

func TestWriteContent001_TrueNegative_RestrictedContentType(t *testing.T) {
	ev := writeScopeEvaluator(t)
	a := uploadPolicyAsset("restricted-policy", map[string]any{
		"operation":               "write",
		"content_type_restricted": true,
		"allowed_content_types":   []any{"image/jpeg", "image/png"},
	})

	result := ev.Evaluate(writeScopeSnapshot(a))

	assertNoWriteScopeFinding(t, result, "CTL.S3.WRITE.CONTENT.001", "restricted-policy")
}

func TestWriteContent001_TrueNegative_ReadOperation(t *testing.T) {
	ev := writeScopeEvaluator(t)
	// Not a write operation — control should not fire
	a := uploadPolicyAsset("read-policy-2", map[string]any{
		"operation":               "read",
		"content_type_restricted": false,
	})

	result := ev.Evaluate(writeScopeSnapshot(a))

	assertNoWriteScopeFinding(t, result, "CTL.S3.WRITE.CONTENT.001", "read-policy-2")
}

// --- Cross-control: same asset, both violations ---

func TestWriteScope_BothViolations(t *testing.T) {
	ev := writeScopeEvaluator(t)
	a := uploadPolicyAsset("bad-policy", map[string]any{
		"operation":               "write",
		"allowed_key_mode":        "prefix",
		"content_type_restricted": false,
	})

	result := ev.Evaluate(writeScopeSnapshot(a))

	assertHasWriteScopeFinding(t, result, "CTL.S3.WRITE.SCOPE.001", "bad-policy")
	assertHasWriteScopeFinding(t, result, "CTL.S3.WRITE.CONTENT.001", "bad-policy")
}
