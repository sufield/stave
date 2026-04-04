package enginetest

// E2E tests for S3 Logging controls (LOG.001, AUDIT.OBJECTLEVEL.001).
//   - LOG.001: kind=bucket AND logging.enabled=false → violation
//   - AUDIT.OBJECTLEVEL.001: kind=bucket AND logging.object_level_logging.enabled=false → violation

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

func logBucket(id string, logging map[string]any) asset.Asset {
	storage := map[string]any{"kind": "bucket"}
	if logging != nil {
		storage["logging"] = logging
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

func logSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

func loadLogControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewRegistry(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.LOG.001":               {},
		"CTL.S3.AUDIT.OBJECTLEVEL.001": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d log controls, found %d", len(ids), len(controls))
	}
	return controls
}

func logEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadLogControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

func assertHasLogFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoLogFinding(t *testing.T, result evaluation.Result, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- LOG.001: Access Logging Required ---

func TestLog001_TruePositive_LoggingDisabled(t *testing.T) {
	ev := logEvaluator(t)
	bucket := logBucket("no-log-bucket", map[string]any{
		"enabled": false,
	})

	result := ev.Evaluate(logSnapshot(bucket))

	assertHasLogFinding(t, result, "CTL.S3.LOG.001", "no-log-bucket")
}

func TestLog001_TrueNegative_LoggingEnabled(t *testing.T) {
	ev := logEvaluator(t)
	bucket := logBucket("logged-bucket", map[string]any{
		"enabled": true,
	})

	result := ev.Evaluate(logSnapshot(bucket))

	assertNoLogFinding(t, result, "CTL.S3.LOG.001", "logged-bucket")
}

// --- AUDIT.OBJECTLEVEL.001: CloudTrail Object-Level Logging ---

func TestAuditObjectLevel001_TruePositive_ObjectLoggingDisabled(t *testing.T) {
	ev := logEvaluator(t)
	bucket := logBucket("no-ct-bucket", map[string]any{
		"object_level_logging": map[string]any{
			"enabled": false,
		},
	})

	result := ev.Evaluate(logSnapshot(bucket))

	assertHasLogFinding(t, result, "CTL.S3.AUDIT.OBJECTLEVEL.001", "no-ct-bucket")
}

func TestAuditObjectLevel001_TrueNegative_ObjectLoggingEnabled(t *testing.T) {
	ev := logEvaluator(t)
	bucket := logBucket("ct-bucket", map[string]any{
		"object_level_logging": map[string]any{
			"enabled": true,
			"source":  "cloudtrail",
		},
	})

	result := ev.Evaluate(logSnapshot(bucket))

	assertNoLogFinding(t, result, "CTL.S3.AUDIT.OBJECTLEVEL.001", "ct-bucket")
}
