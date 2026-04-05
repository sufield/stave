package enginetest

// E2E tests for S3 Versioning controls (VERSION.001, VERSION.002).
//   - VERSION.001: kind=bucket AND versioning.enabled=false → violation
//   - VERSION.002: tags.backup="true" AND versioning.mfa_delete_enabled=false → violation

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

func versionBucket(id string, versioning map[string]any, tags map[string]any) asset.Asset {
	storage := map[string]any{"kind": "bucket"}
	if versioning != nil {
		storage["versioning"] = versioning
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

func versionSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadVersionControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.VERSION.001": {},
		"CTL.S3.VERSION.002": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d version controls, found %d", len(ids), len(controls))
	}
	return controls
}

func versionEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadVersionControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasVersionFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoVersionFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- VERSION.001: Versioning Required (kind=bucket AND enabled=false) ---

func TestVersion001_TruePositive_VersioningDisabled(t *testing.T) {
	ev := versionEvaluator(t)
	bucket := versionBucket("no-ver-bucket", map[string]any{
		"enabled": false,
	}, nil)

	result := ev.Evaluate(versionSnapshot(bucket))

	assertHasVersionFinding(t, result, "CTL.S3.VERSION.001", "no-ver-bucket")
}

func TestVersion001_TrueNegative_VersioningEnabled(t *testing.T) {
	ev := versionEvaluator(t)
	bucket := versionBucket("ver-bucket", map[string]any{
		"enabled": true,
	}, nil)

	result := ev.Evaluate(versionSnapshot(bucket))

	assertNoVersionFinding(t, result, "CTL.S3.VERSION.001", "ver-bucket")
}

// --- VERSION.002: Backup Buckets Must Have MFA Delete ---
// Gated by: tags.backup="true"

func TestVersion002_TruePositive_BackupWithoutMFADelete(t *testing.T) {
	ev := versionEvaluator(t)
	// YAML parses value: "true" as boolean true, so the tag must also be bool true.
	bucket := versionBucket("backup-bucket", map[string]any{
		"mfa_delete_enabled": false,
	}, map[string]any{
		"backup": true,
	})

	result := ev.Evaluate(versionSnapshot(bucket))

	assertHasVersionFinding(t, result, "CTL.S3.VERSION.002", "backup-bucket")
}

func TestVersion002_TrueNegative_BackupWithMFADelete(t *testing.T) {
	ev := versionEvaluator(t)
	bucket := versionBucket("backup-mfa-bucket", map[string]any{
		"mfa_delete_enabled": true,
	}, map[string]any{
		"backup": true,
	})

	result := ev.Evaluate(versionSnapshot(bucket))

	assertNoVersionFinding(t, result, "CTL.S3.VERSION.002", "backup-mfa-bucket")
}

func TestVersion002_TrueNegative_NonBackupBucket(t *testing.T) {
	ev := versionEvaluator(t)
	// Not tagged as backup — control should not fire
	bucket := versionBucket("regular-bucket", map[string]any{
		"mfa_delete_enabled": false,
	}, nil)

	result := ev.Evaluate(versionSnapshot(bucket))

	assertNoVersionFinding(t, result, "CTL.S3.VERSION.002", "regular-bucket")
}
