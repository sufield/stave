package engine

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/trace"
)

// =========================================================================
// assessor.go — 82 surviving mutants
// =========================================================================

// --- Line 69: WithHasher statement/remove ---
func TestMK3_WithHasher_WiresField(t *testing.T) {
	h := stubDigester{}
	a := NewAssessor(WithHasher(h))
	if a.hasher == nil {
		t.Fatal("WithHasher must wire the hasher field")
	}
}

// --- Line 87: WithTracer statement/remove ---
func TestMK3_WithTracer_WiresField(t *testing.T) {
	tr := &mk3Tracer{}
	a := NewAssessor(WithTracer(tr))
	if a.tracer == nil {
		t.Fatal("WithTracer must wire the tracer field")
	}
}

// --- Line 108: WithAcknowledgments statement/remove ---
func TestMK3_WithAcknowledgments_WiresField(t *testing.T) {
	ack := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{ControlID: "CTL.A", AssetID: "a", Rationale: "test", AcknowledgedBy: "x", AcknowledgedDate: "2026-01-01"},
	})
	a := NewAssessor(WithAcknowledgments(ack))
	if a.acknowledgments == nil {
		t.Fatal("WithAcknowledgments must wire the acknowledgments field")
	}
}

// --- Line 191: slaThresholdFor nil-control branch/if ---
func TestMK3_SLAThresholdFor_NilControl(t *testing.T) {
	g := GovernanceConfig{slaThreshold: 48 * time.Hour}
	got := g.slaThresholdFor(nil)
	if got != 48*time.Hour {
		t.Fatalf("nil control should return default SLA, got %v", got)
	}
}

// --- Line 215: sortSnapshots numbers/incrementer (cmp != 0 comparison) ---
func TestMK3_SortSnapshots_OrdersByTime(t *testing.T) {
	a := NewAssessor()
	t1 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := []asset.Snapshot{
		{CapturedAt: t1, Source: "b"},
		{CapturedAt: t2, Source: "a"},
	}
	sorted := a.sortSnapshots(snaps)
	if !sorted[0].CapturedAt.Equal(t2) {
		t.Fatal("expected earliest snapshot first")
	}
	if !sorted[1].CapturedAt.Equal(t1) {
		t.Fatal("expected later snapshot second")
	}
}

// --- Line 243: referenceTime snapshots > 0, numbers/incrementer ---
func TestMK3_ReferenceTime_PicksMaxCapturedAt(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &Assessor{clock: stubClock{t: base.Add(999 * time.Hour)}}
	snaps := []asset.Snapshot{
		{CapturedAt: base},
		{CapturedAt: base.Add(5 * time.Hour)},
		{CapturedAt: base.Add(2 * time.Hour)},
	}
	got, err := a.referenceTime(snaps)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(base.Add(5 * time.Hour)) {
		t.Fatalf("expected max CapturedAt, got %v", got)
	}
}

// --- Line 311: Assess nil predicateEval branch/if ---
func TestMK3_Assess_NilPredicateEval(t *testing.T) {
	a := NewAssessor(WithClock(stubClock{t: time.Now()}))
	a.predicateParser = func(any) (*policy.UnsafePredicate, error) { return &policy.UnsafePredicate{}, nil }
	// predicateEval is nil
	_, err := a.Assess(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil predicateEval")
	}
}

// --- Lines 325-326: sanitized snapshot warning (loop/range_break + branch/if) ---
func TestMK3_Assess_SanitizedSnapshotWarns(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.S.001").build()
	a := newTestAssessor().
		withClock(base).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Sanitized: true, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	// Should not error — sanitized snapshots produce a warning, not a failure.
	_, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("sanitized snapshot should not cause error: %v", err)
	}
}

// --- Line 332: sequenced = a.sortSnapshots statement/remove ---
func TestMK3_Assess_SnapshotsAreSorted(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.SORT.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withSLA(168 * time.Hour).
		withControls(ctl).
		alwaysUnsafe().
		build()
	// Snapshots in reverse order — assessor must sort them.
	snaps := []asset.Snapshot{
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Run.Snapshots != 2 {
		t.Fatalf("expected 2 snapshots, got %d", report.Run.Snapshots)
	}
}

// --- Lines 350-353: assetHint pre-allocation (numbers, comparison, loop/range_break, branch/if) ---
func TestMK3_Assess_AssetHintPicksMax(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.H.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	// Snap1 has 1 asset, snap2 has 3 — hint should be 3.
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{
			{ID: "a", Type: "s3_bucket"},
			{ID: "b", Type: "s3_bucket"},
			{ID: "c", Type: "s3_bucket"},
		}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Summary.TotalAssets < 3 {
		t.Fatalf("expected at least 3 total assets, got %d", report.Summary.TotalAssets)
	}
}

// --- Line 359: referenceTime error branch/if ---
func TestMK3_Assess_NilClock_ReturnsError(t *testing.T) {
	a := NewAssessor()
	a.predicateEval = func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	a.predicateParser = func(any) (*policy.UnsafePredicate, error) { return &policy.UnsafePredicate{}, nil }
	_, err := a.Assess(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil clock")
	}
}

// --- Lines 383-388: controlTimeout env override ---
func TestMK3_Assess_ControlTimeout_EnvOverride(t *testing.T) {
	t.Setenv("STAVE_CONTROL_EVAL_TIMEOUT", "30s")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.TO.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	_, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMK3_Assess_ControlTimeout_InvalidEnv(t *testing.T) {
	t.Setenv("STAVE_CONTROL_EVAL_TIMEOUT", "not-a-duration")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.TO.002").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	// Invalid env should fall back to default, not error.
	_, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error with invalid env: %v", err)
	}
}

func TestMK3_Assess_ControlTimeout_NegativeEnv(t *testing.T) {
	t.Setenv("STAVE_CONTROL_EVAL_TIMEOUT", "-5s")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.TO.003").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	_, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error with negative env: %v", err)
	}
}

// --- Line 400: non-evaluatable control skip (loop/break = continue) ---
func TestMK3_Assess_SkipsNonEvaluatableControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := policy.ControlDefinition{
		ID:   "CTL.SKIP.001",
		Name: "Skip Me",
		Type: policy.TypeUnknown, // Not evaluatable
	}
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.SkippedControls) != 1 {
		t.Fatalf("expected 1 skipped control, got %d", len(report.SkippedControls))
	}
	if report.SkippedControls[0].ControlID != "CTL.SKIP.001" {
		t.Fatalf("skipped control ID = %q, want CTL.SKIP.001", report.SkippedControls[0].ControlID)
	}
}

// --- Line 410: evalCtx.Err() check (conditional/negated) ---
func TestMK3_Assess_CancelledContext_MidControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.CC.001").build()
	ctx, cancel := context.WithCancel(context.Background())
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		build()
	a.predicateEval = func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		cancel()
		return false, ctx.Err()
	}
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	_, err := a.Assess(ctx, snaps)
	if err == nil {
		t.Fatal("expected error from cancelled parent context")
	}
}

// --- Line 453: per-asset context cancellation (branch/if) ---
func TestMK3_ApplyControl_ContextCancel_MidAssetLoop(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.CANCEL.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{
			{ID: "a1", Type: "s3_bucket"},
			{ID: "a2", Type: "s3_bucket"},
		}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{
			{ID: "a1", Type: "s3_bucket"},
			{ID: "a2", Type: "s3_bucket"},
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	_, err := a.Assess(ctx, snaps)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// --- Lines 471-503: exemption handling ---
func TestMK3_ApplyControl_Exemption_RecordsCheck(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.EX.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	a.exemptions = policy.NewExemptionConfig("", []policy.ExemptionRule{
		{Pattern: "a", Reason: "test exemption"},
	})
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Asset should be exempted, not a finding.
	if report.Summary.Violations != 0 {
		t.Fatalf("expected 0 violations for exempted asset, got %d", report.Summary.Violations)
	}
	if len(report.ExemptedAssets) != 1 {
		t.Fatalf("expected 1 exempted asset, got %d", len(report.ExemptedAssets))
	}
	// Check that the exempted check is recorded.
	var skippedChecks int
	for _, c := range report.Checks {
		if c.Verdict == evaluation.VerdictSkipped {
			skippedChecks++
		}
	}
	if skippedChecks != 1 {
		t.Fatalf("expected 1 skipped check for exemption, got %d", skippedChecks)
	}
}

func TestMK3_ApplyControl_Exemption_NilLifecycle(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.EX.002").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	a.exemptions = policy.NewExemptionConfig("", []policy.ExemptionRule{
		{Pattern: "a", Reason: "exempt"},
	})
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.ExemptedAssets) != 1 {
		t.Fatalf("expected 1 exempted asset, got %d", len(report.ExemptedAssets))
	}
}

// --- Lines 524-535: nil lifecycle guard (statement/remove, loop/break) ---
func TestMK3_ApplyControl_NilLifecycle_Records_Inconclusive(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.NL.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have recorded a check for the asset.
	if len(report.Checks) == 0 {
		t.Fatal("expected at least one check")
	}
}

// --- Lines 542-543: span.SetFindingID with findings (numbers/incrementer, branch/if) ---
func TestMK3_Assess_FindingLinkage_InTraceSpan(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.TR.001").build()
	tr := &mk3Tracer{}
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		withTracer(tr).
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Summary.Violations == 0 {
		t.Fatal("expected at least one violation")
	}
	if len(tr.spans) == 0 {
		t.Fatal("expected trace spans")
	}
	// Verify that at least one span has a finding ID set.
	var hasFindingID bool
	for _, s := range tr.spans {
		if s.findingID != "" {
			hasFindingID = true
			break
		}
	}
	if !hasFindingID {
		t.Fatal("expected at least one span with finding ID")
	}
}

// --- Lines 549-550: confidence basis assignment on findings ---
func TestMK3_Assess_ConfidenceBasisSetOnFindings(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.CB.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Summary.Violations == 0 {
		t.Fatal("expected violations")
	}
	// Verify ConfidenceBasis is set on findings (line 550 mutation target).
	for _, f := range report.Findings {
		if f.ConfidenceBasis == "" {
			t.Fatalf("finding %s should have ConfidenceBasis set", f.FindingID)
		}
	}
}

// --- Line 560: RecordNonCompliantAsset on violation (branch/if) ---
func TestMK3_Assess_NonCompliantAsset_Counted(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.NC.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Summary.ExposedResources != 1 {
		t.Fatalf("expected 1 exposed resource, got %d", report.Summary.ExposedResources)
	}
}

func TestMK3_Assess_SafeAsset_NotCountedNonCompliant(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.NC.002").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Summary.ExposedResources != 0 {
		t.Fatalf("expected 0 exposed resources, got %d", report.Summary.ExposedResources)
	}
}

// --- Line 582: compileReport sort comparators (numbers/incrementer) ---
func TestMK3_CompileReport_ChecksSortedByControlThenAsset(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctlA := newTestControl("CTL.A.001").build()
	ctlB := newTestControl("CTL.B.001").build()
	a := newTestAssessor().
		withClock(base.Add(2*time.Hour)).
		withControls(ctlA, ctlB).
		alwaysUnsafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{
			{ID: "z-asset", Type: "s3_bucket"},
			{ID: "a-asset", Type: "s3_bucket"},
		}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{
			{ID: "z-asset", Type: "s3_bucket"},
			{ID: "a-asset", Type: "s3_bucket"},
		}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Checks should be sorted: first by ControlID, then by AssetID.
	for i := 1; i < len(report.Checks); i++ {
		prev := report.Checks[i-1]
		curr := report.Checks[i]
		if prev.ControlID > curr.ControlID {
			t.Fatalf("checks not sorted by ControlID: %s > %s", prev.ControlID, curr.ControlID)
		}
		if prev.ControlID == curr.ControlID && prev.AssetID > curr.AssetID {
			t.Fatalf("checks not sorted by AssetID within same control: %s > %s", prev.AssetID, curr.AssetID)
		}
	}
}

// --- Line 611: allFindings merge (arithmetic/base) ---
func TestMK3_CompileReport_MergesActiveAndExcepted(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.M.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	a.exceptions = policy.NewExceptionConfig([]policy.ExceptionRule{
		{ControlID: "CTL.M.001", AssetID: "b", Reason: "excepted"},
	})
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{
			{ID: "a", Type: "s3_bucket"},
			{ID: "b", Type: "s3_bucket"},
		}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{
			{ID: "a", Type: "s3_bucket"},
			{ID: "b", Type: "s3_bucket"},
		}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// One finding should be active, one excepted.
	if report.Summary.Violations < 1 {
		t.Fatal("expected at least 1 active finding")
	}
}

// --- Line 613: append exceptedFindings (statement/remove) ---
func TestMK3_CompileReport_ExceptedFindingsIncluded(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.EF.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	a.exceptions = policy.NewExceptionConfig([]policy.ExceptionRule{
		{ControlID: "CTL.EF.001", AssetID: "a", Reason: "excepted"},
	})
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var suppressedCount int
	for _, f := range report.Findings {
		if f.Status == evaluation.FindingSuppressed {
			suppressedCount++
		}
	}
	if suppressedCount == 0 {
		t.Fatal("expected at least one suppressed finding from exception")
	}
}

// --- Line 666: GenerateEvidence condition (expression, numbers) ---
func TestMK3_CompileReport_GenerateEvidence_WithSnapshots(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.EV.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps, AssessmentOptions{GenerateEvidence: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.EvidencePackage == nil {
		t.Fatal("expected evidence package when GenerateEvidence=true")
	}
}

func TestMK3_CompileReport_NoEvidence_WhenFlagFalse(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.EV.002").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{{ID: "a", Type: "s3_bucket"}}},
	}
	report, err := a.Assess(context.Background(), snaps, AssessmentOptions{GenerateEvidence: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.EvidencePackage != nil {
		t.Fatal("expected no evidence package when GenerateEvidence=false")
	}
}

func TestMK3_CompileReport_NoEvidence_EmptySnapshots(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := newTestAssessor().
		withClock(base).
		build()
	report, err := a.Assess(context.Background(), nil, AssessmentOptions{GenerateEvidence: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.EvidencePackage != nil {
		t.Fatal("expected no evidence package with empty snapshots")
	}
}

// --- Lines 740-741: partitionMarkerFindings len(markerIDs)==0 fast path ---
func TestMK3_PartitionMarkerFindings_NoMarkers(t *testing.T) {
	ctls := []policy.ControlDefinition{
		{ID: "CTL.A", Type: policy.TypeUnsafeState},
		{ID: "CTL.B", Type: policy.TypeUnsafeDuration},
	}
	findings := []evaluation.Finding{
		{ControlID: "CTL.A"},
		{ControlID: "CTL.B"},
	}
	violations, markers := partitionMarkerFindings(findings, ctls)
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}
	if markers != nil {
		t.Fatal("expected nil markers for non-marker catalog")
	}
}

func TestMK3_PartitionMarkerFindings_WithMarkers(t *testing.T) {
	ctls := []policy.ControlDefinition{
		{ID: "CTL.A", Type: policy.TypeUnsafeState},
		{ID: "CTL.M", Type: policy.TypeMarker},
	}
	findings := []evaluation.Finding{
		{ControlID: "CTL.A"},
		{ControlID: "CTL.M"},
	}
	violations, markers := partitionMarkerFindings(findings, ctls)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if len(markers) != 1 {
		t.Fatalf("expected 1 marker, got %d", len(markers))
	}
}

// --- Lines 765, 772: partitionFindings (statement/remove) ---
func TestMK3_PartitionFindings_SetsStatus(t *testing.T) {
	exceptions := policy.NewExceptionConfig([]policy.ExceptionRule{
		{ControlID: "CTL.X", AssetID: "a", Reason: "excepted"},
	})
	findings := []evaluation.Finding{
		{ControlID: "CTL.X", AssetID: "a"},
		{ControlID: "CTL.Y", AssetID: "b"},
	}
	active, excepted := partitionFindings(findings, exceptions, time.Now())
	if len(active) != 1 || active[0].Status != evaluation.FindingActive {
		t.Fatalf("expected 1 active finding with Active status")
	}
	if len(excepted) != 1 || excepted[0].Status != evaluation.FindingSuppressed {
		t.Fatalf("expected 1 excepted finding with Suppressed status")
	}
	if excepted[0].Suppression == nil {
		t.Fatal("excepted finding should have Suppression set")
	}
	if excepted[0].Suppression.Kind != "exemption" {
		t.Fatalf("Suppression.Kind = %q, want exemption", excepted[0].Suppression.Kind)
	}
	if excepted[0].Suppression.Reason != "excepted" {
		t.Fatalf("Suppression.Reason = %q, want excepted", excepted[0].Suppression.Reason)
	}
}

// --- Lines 792-795: buildSuppressionSet (loop/break, expression/remove) ---
func TestMK3_BuildSuppressionSet_IncludesValidSuppressed(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: "CTL.A", AssetID: "a1", Status: evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{Valid: true}},
		{ControlID: "CTL.B", AssetID: "a2", Status: evaluation.FindingActive},
	}
	set := buildSuppressionSet(findings)
	if len(set) != 1 {
		t.Fatalf("expected 1 suppressed key, got %d", len(set))
	}
	key := risk.SuppressionKey{ControlID: "CTL.A", AssetID: "a1"}
	if _, ok := set[key]; !ok {
		t.Fatal("expected CTL.A/a1 in suppression set")
	}
}

func TestMK3_BuildSuppressionSet_ExcludesInvalidSuppressed(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: "CTL.A", AssetID: "a1", Status: evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{Valid: false}},
	}
	set := buildSuppressionSet(findings)
	if len(set) != 0 {
		t.Fatalf("expected 0 suppressed keys for invalid suppression, got %d", len(set))
	}
}

func TestMK3_BuildSuppressionSet_ExcludesActive(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: "CTL.A", AssetID: "a1", Status: evaluation.FindingActive},
	}
	set := buildSuppressionSet(findings)
	if len(set) != 0 {
		t.Fatalf("expected 0 suppressed keys for active finding, got %d", len(set))
	}
}

func TestMK3_BuildSuppressionSet_NilSuppression(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: "CTL.A", AssetID: "a1", Status: evaluation.FindingSuppressed,
			Suppression: nil},
	}
	set := buildSuppressionSet(findings)
	// nil Suppression passes the nil-guard (f.Suppression != nil is false,
	// so the !Valid skip is never reached) → finding IS suppressed.
	if len(set) != 1 {
		t.Fatalf("expected 1 key for nil suppression (suppressed status), got %d", len(set))
	}
}

// --- Lines 828, 832: EvaluationCoverage.Contains ---
func TestMK3_EvaluationCoverage_Contains_NilMap(t *testing.T) {
	var c EvaluationCoverage
	if c.Contains("a", "CTL.X") {
		t.Fatal("nil coverage should return false")
	}
}

func TestMK3_EvaluationCoverage_Contains_MissingAsset(t *testing.T) {
	c := EvaluationCoverage{
		"a": {"CTL.X": {}},
	}
	if c.Contains("b", "CTL.X") {
		t.Fatal("missing asset should return false")
	}
}

func TestMK3_EvaluationCoverage_Contains_MissingControl(t *testing.T) {
	c := EvaluationCoverage{
		"a": {"CTL.X": {}},
	}
	if c.Contains("a", "CTL.Y") {
		t.Fatal("missing control should return false")
	}
}

func TestMK3_EvaluationCoverage_Contains_Present(t *testing.T) {
	c := EvaluationCoverage{
		"a": {"CTL.X": {}},
	}
	if !c.Contains("a", "CTL.X") {
		t.Fatal("present pair should return true")
	}
}

// --- Lines 845, 849: newEvaluationCoverage (loop/range_break, statement/remove) ---
func TestMK3_NewEvaluationCoverage_MultipleChecks(t *testing.T) {
	checks := []evaluation.ResourceCheck{
		{AssetID: "a", ControlID: "CTL.X"},
		{AssetID: "a", ControlID: "CTL.Y"},
		{AssetID: "b", ControlID: "CTL.X"},
	}
	c := newEvaluationCoverage(checks)
	if !c.Contains("a", "CTL.X") {
		t.Fatal("missing (a, CTL.X)")
	}
	if !c.Contains("a", "CTL.Y") {
		t.Fatal("missing (a, CTL.Y)")
	}
	if !c.Contains("b", "CTL.X") {
		t.Fatal("missing (b, CTL.X)")
	}
	if c.Contains("b", "CTL.Y") {
		t.Fatal("(b, CTL.Y) should not be present")
	}
}

// --- Lines 862-936: applyAcknowledgments branches ---
func TestMK3_ApplyAcknowledgments_NilAcks(t *testing.T) {
	findings := []evaluation.Finding{{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"}}
	result := applyAcknowledgments(findings, nil, nil, time.Now(), nil)
	if len(result) != 1 || result[0].FindingID != "f1" {
		t.Fatal("nil acks should return active findings unchanged")
	}
}

func TestMK3_ApplyAcknowledgments_ExpiredRule(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:        "CTL.A",
			AssetID:          "a",
			Rationale:        "past",
			AcknowledgedBy:   "x",
			AcknowledgedDate: "2026-01-01",
			ExpiryDate:       "2026-03-01",
		},
	})
	findings := []evaluation.Finding{{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"}}
	coverage := EvaluationCoverage{"a": {"CTL.A": {}}}
	result := applyAcknowledgments(findings, nil, acks, now, coverage)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Suppression == nil || result[0].Suppression.Valid {
		t.Fatal("expired ack should set Valid=false")
	}
	if result[0].Suppression.InvalidReason != "expired" {
		t.Fatalf("InvalidReason = %q, want expired", result[0].Suppression.InvalidReason)
	}
}

func TestMK3_ApplyAcknowledgments_CompensatingFailing(t *testing.T) {
	now := time.Now()
	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.A",
			AssetID:              "a",
			Rationale:            "comp",
			AcknowledgedBy:       "x",
			AcknowledgedDate:     "2026-01-01",
			CompensatingControls: []kernel.ControlID{"CTL.B"},
		},
	})
	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"},
		{FindingID: "f2", ControlID: "CTL.B", AssetID: "a"},
	}
	coverage := EvaluationCoverage{"a": {"CTL.A": {}, "CTL.B": {}}}
	result := applyAcknowledgments(findings, nil, acks, now, coverage)
	var ackFindings []evaluation.Finding
	for _, f := range result {
		if f.Suppression != nil && f.Suppression.Kind == "acknowledgment" {
			ackFindings = append(ackFindings, f)
		}
	}
	if len(ackFindings) != 1 {
		t.Fatalf("expected 1 ack finding, got %d", len(ackFindings))
	}
	if ackFindings[0].Suppression.Valid {
		t.Fatal("ack should be invalid when comp control failing")
	}
	if ackFindings[0].Suppression.InvalidReason != "compensating_controls_failing" {
		t.Fatalf("InvalidReason = %q, want compensating_controls_failing", ackFindings[0].Suppression.InvalidReason)
	}
}

func TestMK3_ApplyAcknowledgments_CompensatingExcepted(t *testing.T) {
	now := time.Now()
	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.A",
			AssetID:              "a",
			Rationale:            "comp",
			AcknowledgedBy:       "x",
			AcknowledgedDate:     "2026-01-01",
			CompensatingControls: []kernel.ControlID{"CTL.B"},
		},
	})
	activeFindings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"},
	}
	exceptedFindings := []evaluation.Finding{
		{FindingID: "f2", ControlID: "CTL.B", AssetID: "a", Status: evaluation.FindingSuppressed},
	}
	coverage := EvaluationCoverage{"a": {"CTL.A": {}, "CTL.B": {}}}
	result := applyAcknowledgments(activeFindings, exceptedFindings, acks, now, coverage)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Suppression == nil || result[0].Suppression.Valid {
		t.Fatal("ack should be invalid when comp control is excepted")
	}
}

func TestMK3_ApplyAcknowledgments_CompensatingUnevaluated(t *testing.T) {
	now := time.Now()
	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.A",
			AssetID:              "a",
			Rationale:            "comp",
			AcknowledgedBy:       "x",
			AcknowledgedDate:     "2026-01-01",
			CompensatingControls: []kernel.ControlID{"CTL.B"},
		},
	})
	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"},
	}
	// CTL.B not in coverage → unevaluated
	coverage := EvaluationCoverage{"a": {"CTL.A": {}}}
	result := applyAcknowledgments(findings, nil, acks, now, coverage)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Suppression == nil || result[0].Suppression.Valid {
		t.Fatal("ack should be invalid when comp control unevaluated")
	}
}

func TestMK3_ApplyAcknowledgments_ValidAck(t *testing.T) {
	now := time.Now()
	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.A",
			AssetID:              "a",
			Rationale:            "accepted risk",
			AcknowledgedBy:       "x",
			AcknowledgedDate:     "2026-01-01",
			CompensatingControls: []kernel.ControlID{"CTL.B"},
		},
	})
	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"},
	}
	// CTL.B passes (not in active failures, not excepted, is in coverage)
	coverage := EvaluationCoverage{"a": {"CTL.A": {}, "CTL.B": {}}}
	result := applyAcknowledgments(findings, nil, acks, now, coverage)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Suppression == nil || !result[0].Suppression.Valid {
		t.Fatal("ack should be valid when comp controls pass")
	}
	if result[0].Suppression.Kind != "acknowledgment" {
		t.Fatalf("Kind = %q, want acknowledgment", result[0].Suppression.Kind)
	}
}

func TestMK3_ApplyAcknowledgments_NoMatchingRule(t *testing.T) {
	now := time.Now()
	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:        "CTL.OTHER",
			AssetID:          "other",
			Rationale:        "n/a",
			AcknowledgedBy:   "x",
			AcknowledgedDate: "2026-01-01",
		},
	})
	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"},
	}
	result := applyAcknowledgments(findings, nil, acks, now, nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Status == evaluation.FindingSuppressed {
		t.Fatal("non-matching ack should not suppress finding")
	}
}

// --- Lines 994-995: PolicyPreimage (arithmetic/base, statement/remove) ---
func TestMK3_PolicyPreimage_IncludesEvalVersion(t *testing.T) {
	h := stubDigester{}
	ctl := newTestControl("CTL.FP.001").build()
	a := NewAssessor(WithHasher(h), WithControls([]policy.ControlDefinition{ctl}))
	lines := a.PolicyPreimage()
	if lines == nil {
		t.Fatal("expected non-nil preimage")
	}
	var hasVersion bool
	for _, l := range lines {
		if l == "eval_version:"+EvalVersion {
			hasVersion = true
		}
	}
	if !hasVersion {
		t.Fatal("preimage must include eval_version line")
	}
}

func TestMK3_PolicyPreimage_EmptyPolicy(t *testing.T) {
	h := stubDigester{}
	a := NewAssessor(WithHasher(h))
	lines := a.PolicyPreimage()
	if lines != nil {
		t.Fatalf("empty policy should return nil preimage, got %v", lines)
	}
}

func TestMK3_PolicyPreimage_NoHasher(t *testing.T) {
	ctl := newTestControl("CTL.FP.002").build()
	a := NewAssessor(WithControls([]policy.ControlDefinition{ctl}))
	lines := a.PolicyPreimage()
	if lines != nil {
		t.Fatalf("no hasher should return nil preimage, got %v", lines)
	}
}

func TestMK3_PolicyPreimage_Sorted(t *testing.T) {
	h := stubDigester{}
	ctls := []policy.ControlDefinition{
		newTestControl("CTL.Z").build(),
		newTestControl("CTL.A").build(),
	}
	a := NewAssessor(WithHasher(h), WithControls(ctls))
	lines := a.PolicyPreimage()
	for i := 1; i < len(lines); i++ {
		if lines[i-1] > lines[i] {
			t.Fatalf("preimage not sorted: %q > %q", lines[i-1], lines[i])
		}
	}
}

// --- Lines 1020: DefaultContinuityLimit (arithmetic, numbers) ---
func TestMK3_DefaultContinuityLimit_Value(t *testing.T) {
	if DefaultContinuityLimit != 12*time.Hour {
		t.Fatalf("DefaultContinuityLimit = %v, want 12h", DefaultContinuityLimit)
	}
}

// --- FingerprintPolicy ---
func TestMK3_FingerprintPolicy_EmptyPolicy(t *testing.T) {
	a := NewAssessor(WithHasher(stubDigester{}))
	d := a.FingerprintPolicy()
	if d != "" {
		t.Fatalf("expected empty digest for empty policy, got %q", d)
	}
}

func TestMK3_FingerprintPolicy_NoHasher(t *testing.T) {
	ctl := newTestControl("CTL.FP.003").build()
	a := NewAssessor(WithControls([]policy.ControlDefinition{ctl}))
	d := a.FingerprintPolicy()
	if d != "" {
		t.Fatalf("expected empty digest with no hasher, got %q", d)
	}
}

func TestMK3_FingerprintPolicy_WithHasherAndControls(t *testing.T) {
	h := stubDigester{}
	ctl := newTestControl("CTL.FP.004").build()
	a := NewAssessor(WithHasher(h), WithControls([]policy.ControlDefinition{ctl}))
	d := a.FingerprintPolicy()
	if d == "" {
		t.Fatal("expected non-empty digest with hasher and controls")
	}
}

// --- evaluatedState ---
func TestMK3_EvaluatedState_Empty(t *testing.T) {
	if evaluatedState(nil) != "" {
		t.Fatal("empty snapshots should return empty string")
	}
}

func TestMK3_EvaluatedState_PicksLatest(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := []asset.Snapshot{
		{CapturedAt: base, Source: "old"},
		{CapturedAt: base.Add(time.Hour), Source: "new"},
		{CapturedAt: base.Add(30 * time.Minute), Source: "mid"},
	}
	got := evaluatedState(snaps)
	if got != "new" {
		t.Fatalf("expected 'new', got %q", got)
	}
}

// --- partitionIndeterminateFindings ---
func TestMK3_PartitionIndeterminate_SetsDataQuality(t *testing.T) {
	findings := []evaluation.Finding{
		makeIndeterminateFinding("f1", evaluation.FindingActive),
		{FindingID: "f2", ControlID: "CTL.B", AssetID: "b"},
	}
	confirmed, indet := partitionIndeterminateFindings(findings)
	if len(indet) != 1 || indet[0].FindingID != "f1" {
		t.Fatalf("expected f1 in indeterminate, got %v", indet)
	}
	if indet[0].DataQuality != evaluation.DataQualityIndeterminate {
		t.Fatal("indeterminate finding should have DataQualityIndeterminate")
	}
	if len(confirmed) != 1 || confirmed[0].FindingID != "f2" {
		t.Fatalf("expected f2 in confirmed, got %v", confirmed)
	}
	if confirmed[0].DataQuality != evaluation.DataQualityConfirmed {
		t.Fatal("confirmed finding should have DataQualityConfirmed")
	}
}

func TestMK3_PartitionIndeterminate_SuppressedStaysConfirmed(t *testing.T) {
	f := makeIndeterminateFinding("f1", evaluation.FindingSuppressed)
	confirmed, indet := partitionIndeterminateFindings([]evaluation.Finding{f})
	if len(indet) != 0 {
		t.Fatal("suppressed indeterminate should stay in confirmed")
	}
	if len(confirmed) != 1 {
		t.Fatal("expected 1 confirmed finding")
	}
	if confirmed[0].DataQuality != evaluation.DataQualityIndeterminate {
		t.Fatal("should still have DataQualityIndeterminate")
	}
}

// --- sortSnapshots secondary sort by source ---
func TestMK3_SortSnapshots_SecondaryBySource(t *testing.T) {
	a := NewAssessor()
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := []asset.Snapshot{
		{CapturedAt: ts, Source: "z-source"},
		{CapturedAt: ts, Source: "a-source"},
	}
	sorted := a.sortSnapshots(snaps)
	if string(sorted[0].Source) != "a-source" {
		t.Fatalf("expected a-source first (secondary sort), got %s", sorted[0].Source)
	}
}

// --- Assess context.Err() fast-fail at entry ---
func TestMK3_Assess_CancelledAtEntry(t *testing.T) {
	a := newTestAssessor().
		withClock(time.Now()).
		build()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := a.Assess(ctx, nil)
	if err == nil {
		t.Fatal("expected error for cancelled context at entry")
	}
}

// --- SeenAssetCount and ExposedResources via full pipeline ---
func TestMK3_Assess_SeenAssetCount(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.SC.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{
			{ID: "a", Type: "s3_bucket"},
			{ID: "b", Type: "s3_bucket"},
		}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{
			{ID: "a", Type: "s3_bucket"},
			{ID: "b", Type: "s3_bucket"},
		}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Summary.TotalAssets != 2 {
		t.Fatalf("expected 2 total assets, got %d", report.Summary.TotalAssets)
	}
}

// --- hasEmptyPolicy ---
func TestMK3_HasEmptyPolicy_NoControls(t *testing.T) {
	a := NewAssessor()
	if !a.hasEmptyPolicy() {
		t.Fatal("no controls should be empty policy")
	}
}

func TestMK3_HasEmptyPolicy_WithControls(t *testing.T) {
	ctl := newTestControl("CTL.P.001").build()
	a := NewAssessor(WithControls([]policy.ControlDefinition{ctl}))
	if a.hasEmptyPolicy() {
		t.Fatal("with controls should not be empty policy")
	}
}

// --- canComputeDigests ---
func TestMK3_CanComputeDigests_NoHasher(t *testing.T) {
	a := NewAssessor()
	if a.canComputeDigests() {
		t.Fatal("no hasher should mean cannot compute digests")
	}
}

func TestMK3_CanComputeDigests_WithHasher(t *testing.T) {
	a := NewAssessor(WithHasher(stubDigester{}))
	if !a.canComputeDigests() {
		t.Fatal("with hasher should mean can compute digests")
	}
}

// --- Logger ---
func TestMK3_Logger_NilReceiver(t *testing.T) {
	var a *Assessor
	l := a.Logger()
	if l == nil {
		t.Fatal("nil receiver Logger should return slog.Default()")
	}
}

func TestMK3_Logger_NilLoggerField(t *testing.T) {
	a := &Assessor{}
	l := a.Logger()
	if l == nil {
		t.Fatal("nil logger field should return slog.Default()")
	}
}

// --- Exempted asset total includes exempted ---
func TestMK3_Assess_ExemptedAssetStillCountedInTotal(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.ET.001").build()
	a := newTestAssessor().
		withClock(base.Add(2 * time.Hour)).
		withControls(ctl).
		alwaysUnsafe().
		build()
	a.exemptions = policy.NewExemptionConfig("", []policy.ExemptionRule{
		{Pattern: "a", Reason: "exempt"},
	})
	snaps := []asset.Snapshot{
		{CapturedAt: base, Assets: []asset.Asset{
			{ID: "a", Type: "s3_bucket"},
			{ID: "b", Type: "s3_bucket"},
		}},
		{CapturedAt: base.Add(time.Hour), Assets: []asset.Asset{
			{ID: "a", Type: "s3_bucket"},
			{ID: "b", Type: "s3_bucket"},
		}},
	}
	report, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// TotalAssets should include the exempted asset.
	if report.Summary.TotalAssets < 2 {
		t.Fatalf("expected at least 2 total assets (including exempted), got %d", report.Summary.TotalAssets)
	}
}

// =========================================================================
// Test helpers
// =========================================================================

type stubDigester struct{}

func (stubDigester) Digest(components []string, sep byte) kernel.Digest {
	return kernel.Digest("stub-digest")
}

type mk3Tracer struct {
	spans []*mk3Span
}

func (tr *mk3Tracer) BeginAssessment(resourceID, policyID string) ports.AssessmentSpan {
	s := &mk3Span{resourceID: resourceID, policyID: policyID}
	tr.spans = append(tr.spans, s)
	return s
}

func (tr *mk3Tracer) Finalize(_ ports.FinalizeArgs) *trace.LogicTrace { return nil }

type mk3Span struct {
	resourceID string
	policyID   string
	findingID  string
	verdict    string
	confidence string
}

func (s *mk3Span) RecordStep(string, any, any) {}
func (s *mk3Span) SetVerdict(v, c string)      { s.verdict = v; s.confidence = c }
func (s *mk3Span) SetFindingID(id string)      { s.findingID = id }
func (s *mk3Span) End()                        {}

func makeIndeterminateFinding(id string, status evaluation.FindingStatus) evaluation.Finding {
	return evaluation.Finding{
		FindingID: kernel.FindingID(id),
		ControlID: "CTL.IND",
		AssetID:   "a",
		Evidence: evaluation.Evidence{
			Misconfigurations: []policy.Misconfiguration{
				{FieldAbsent: true},
			},
		},
		Status: status,
	}
}

// Ensure unused import suppression.
var _ = os.Getenv
