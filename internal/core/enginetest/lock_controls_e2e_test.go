package enginetest

// E2E tests for S3 Object Lock controls (LOCK.001, LOCK.002, LOCK.003).
//   - LOCK.001: compliance-tagged bucket + object_lock.enabled=false → violation
//   - LOCK.002: PHI bucket + object_lock.enabled=true + mode != COMPLIANCE → violation
//   - LOCK.003: PHI bucket + object_lock.enabled=true + retention_days < 2190 → violation

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

func lockBucket(id string, objectLock map[string]any, tags map[string]any) asset.Asset {
	storage := map[string]any{"kind": "bucket"}
	if objectLock != nil {
		storage["object_lock"] = objectLock
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

func lockSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadLockControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.LOCK.001": {},
		"CTL.S3.LOCK.002": {},
		"CTL.S3.LOCK.003": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d lock controls, found %d", len(ids), len(controls))
	}
	return controls
}

func lockEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadLockControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasLockFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoLockFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- LOCK.001: Compliance-Tagged Buckets Must Have Object Lock ---
// Gated by: kind=bucket AND tags.compliance present

func TestLock001_TruePositive_ComplianceTaggedNoLock(t *testing.T) {
	ev := lockEvaluator(t)
	bucket := lockBucket("no-lock-bucket", map[string]any{
		"enabled": false,
	}, map[string]any{
		"compliance": "hipaa",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertHasLockFinding(t, result, "CTL.S3.LOCK.001", "no-lock-bucket")
}

func TestLock001_TrueNegative_ComplianceTaggedWithLock(t *testing.T) {
	ev := lockEvaluator(t)
	bucket := lockBucket("locked-bucket", map[string]any{
		"enabled": true,
	}, map[string]any{
		"compliance": "soc2",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertNoLockFinding(t, result, "CTL.S3.LOCK.001", "locked-bucket")
}

func TestLock001_TrueNegative_NoComplianceTag(t *testing.T) {
	ev := lockEvaluator(t)
	// No compliance tag — control should not fire
	bucket := lockBucket("untagged-bucket", map[string]any{
		"enabled": false,
	}, nil)

	result := ev.Evaluate(lockSnapshot(bucket))

	assertNoLockFinding(t, result, "CTL.S3.LOCK.001", "untagged-bucket")
}

// --- LOCK.002: PHI Buckets Must Use COMPLIANCE Mode ---
// Gated by: tags.data-classification=phi AND object_lock.enabled=true

func TestLock002_TruePositive_PHIWithGovernanceMode(t *testing.T) {
	ev := lockEvaluator(t)
	bucket := lockBucket("phi-gov-bucket", map[string]any{
		"enabled": true,
		"mode":    "GOVERNANCE",
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertHasLockFinding(t, result, "CTL.S3.LOCK.002", "phi-gov-bucket")
}

func TestLock002_TrueNegative_PHIWithComplianceMode(t *testing.T) {
	ev := lockEvaluator(t)
	bucket := lockBucket("phi-comp-bucket", map[string]any{
		"enabled": true,
		"mode":    "COMPLIANCE",
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertNoLockFinding(t, result, "CTL.S3.LOCK.002", "phi-comp-bucket")
}

func TestLock002_TrueNegative_NonPHIBucket(t *testing.T) {
	ev := lockEvaluator(t)
	// Not PHI — control should not fire even with GOVERNANCE mode
	bucket := lockBucket("internal-bucket", map[string]any{
		"enabled": true,
		"mode":    "GOVERNANCE",
	}, map[string]any{
		"data-classification": "internal",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertNoLockFinding(t, result, "CTL.S3.LOCK.002", "internal-bucket")
}

// --- LOCK.003: PHI Object Lock Retention Must Meet Minimum Period ---
// Gated by: tags.data-classification=phi AND object_lock.enabled=true
// Unsafe when: retention_days < 2190

func TestLock003_TruePositive_ShortRetention(t *testing.T) {
	ev := lockEvaluator(t)
	bucket := lockBucket("short-retention-bucket", map[string]any{
		"enabled":        true,
		"retention_days": 365,
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertHasLockFinding(t, result, "CTL.S3.LOCK.003", "short-retention-bucket")
}

func TestLock003_TrueNegative_SufficientRetention(t *testing.T) {
	ev := lockEvaluator(t)
	bucket := lockBucket("long-retention-bucket", map[string]any{
		"enabled":        true,
		"retention_days": 2555,
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertNoLockFinding(t, result, "CTL.S3.LOCK.003", "long-retention-bucket")
}

func TestLock003_TrueNegative_ExactMinimumRetention(t *testing.T) {
	ev := lockEvaluator(t)
	// Exactly 2190 — should NOT fire (lt means strictly less than)
	bucket := lockBucket("exact-retention-bucket", map[string]any{
		"enabled":        true,
		"retention_days": 2190,
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertNoLockFinding(t, result, "CTL.S3.LOCK.003", "exact-retention-bucket")
}

func TestLock003_TrueNegative_NonPHIBucket(t *testing.T) {
	ev := lockEvaluator(t)
	// Not PHI — control should not fire
	bucket := lockBucket("internal-bucket", map[string]any{
		"enabled":        true,
		"retention_days": 30,
	}, map[string]any{
		"data-classification": "internal",
	})

	result := ev.Evaluate(lockSnapshot(bucket))

	assertNoLockFinding(t, result, "CTL.S3.LOCK.003", "internal-bucket")
}
