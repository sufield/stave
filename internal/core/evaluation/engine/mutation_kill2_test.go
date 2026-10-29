package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
)

// =========================================================================
// strategy.go — Cluster 10 (88 survivors)
// =========================================================================

// --- buildStrategy ---

func TestBuildStrategy_UnknownType(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.UNK.001", Type: policy.ControlType(99)}
	s := buildStrategy(testAssessor(time.Hour, time.Now()), ctl)
	if _, ok := s.(*unsupportedStrategy); !ok {
		t.Fatalf("expected unsupportedStrategy, got %T", s)
	}
}

func TestBuildStrategy_UnsafeState(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.S.001", Type: policy.TypeUnsafeState}
	s := buildStrategy(testAssessor(time.Hour, time.Now()), ctl)
	if _, ok := s.(*unsafeStateStrategy); !ok {
		t.Fatalf("expected unsafeStateStrategy, got %T", s)
	}
}

func TestBuildStrategy_UnsafeDuration(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.D.001", Type: policy.TypeUnsafeDuration}
	s := buildStrategy(testAssessor(time.Hour, time.Now()), ctl)
	if _, ok := s.(*unsafeDurationStrategy); !ok {
		t.Fatalf("expected unsafeDurationStrategy, got %T", s)
	}
}

func TestBuildStrategy_UnsafeRecurrence(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.R.001", Type: policy.TypeUnsafeRecurrence}
	s := buildStrategy(testAssessor(time.Hour, time.Now()), ctl)
	if _, ok := s.(*unsafeRecurrenceStrategy); !ok {
		t.Fatalf("expected unsafeRecurrenceStrategy, got %T", s)
	}
}

func TestBuildStrategy_PrefixExposure(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.P.001", Type: policy.TypePrefixExposure}
	s := buildStrategy(testAssessor(time.Hour, time.Now()), ctl)
	if _, ok := s.(*prefixExposureStrategy); !ok {
		t.Fatalf("expected prefixExposureStrategy, got %T", s)
	}
}

func TestBuildStrategy_Marker(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.M.001", Type: policy.TypeMarker}
	s := buildStrategy(testAssessor(time.Hour, time.Now()), ctl)
	if _, ok := s.(*unsafeStateStrategy); !ok {
		t.Fatalf("expected unsafeStateStrategy for marker, got %T", s)
	}
}

// --- newControlRow ---

func TestNewControlRow_NilControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})

	row := newControlRow(nil, tl)
	if row.ControlID != "" {
		t.Fatalf("nil control should produce empty ControlID, got %q", row.ControlID)
	}
}

func TestNewControlRow_NilLifecycle(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.X.001"}
	row := newControlRow(ctl, nil)
	if row.ControlID != "CTL.X.001" {
		t.Fatalf("expected ControlID CTL.X.001, got %q", row.ControlID)
	}
	if row.AssetID != "" {
		t.Fatalf("nil lifecycle should leave AssetID empty, got %q", row.AssetID)
	}
}

func TestNewControlRow_HappyPath(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})

	ctl := &policy.ControlDefinition{ID: "CTL.X.001"}
	row := newControlRow(ctl, tl)
	if row.ControlID != "CTL.X.001" {
		t.Fatalf("expected ControlID CTL.X.001, got %q", row.ControlID)
	}
	if row.AssetID == "" {
		t.Fatal("expected non-empty AssetID")
	}
	if row.AssetType == "" {
		t.Fatal("expected non-empty AssetType")
	}
}

// --- finalizeRow ---

func TestFinalizeRow_SetsVerdictAndConfidence(t *testing.T) {
	row := evaluation.ResourceCheck{ControlID: "CTL.A"}
	result := finalizeRow(row, evaluation.VerdictViolation, evaluation.ConfidenceLow)
	if result.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected VerdictViolation, got %v", result.Verdict)
	}
	if result.Confidence != evaluation.ConfidenceLow {
		t.Fatalf("expected ConfidenceLow, got %v", result.Confidence)
	}
}

func TestFinalizeRow_PreservesExistingFields(t *testing.T) {
	row := evaluation.ResourceCheck{ControlID: "CTL.B", AssetID: "a-1"}
	result := finalizeRow(row, evaluation.VerdictPass, evaluation.ConfidenceHigh)
	if result.ControlID != "CTL.B" {
		t.Fatalf("expected ControlID preserved, got %q", result.ControlID)
	}
	if result.AssetID != "a-1" {
		t.Fatalf("expected AssetID preserved, got %q", result.AssetID)
	}
}

// --- Nil guards on all strategies ---

func TestNilGuard_UnsafeState_NilControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})
	s := &unsafeStateStrategy{deps: testAssessor(time.Hour, base), ctl: nil}
	row, findings := s.Evaluate(tl, base, IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil control should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil control should yield nil findings")
	}
}

func TestNilGuard_UnsafeState_NilLifecycle(t *testing.T) {
	ctl := testControl("CTL.S.001", policy.TypeUnsafeState)
	s := &unsafeStateStrategy{deps: testAssessor(time.Hour, time.Now()), ctl: ctl}
	row, findings := s.Evaluate(nil, time.Now(), IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil lifecycle should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil lifecycle should yield nil findings")
	}
}

func TestNilGuard_UnsafeDuration_NilControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})
	s := &unsafeDurationStrategy{deps: testAssessor(time.Hour, base), ctl: nil}
	row, findings := s.Evaluate(tl, base, IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil control should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil control should yield nil findings")
	}
}

func TestNilGuard_UnsafeDuration_NilLifecycle(t *testing.T) {
	ctl := testControl("CTL.D.001", policy.TypeUnsafeDuration)
	s := &unsafeDurationStrategy{deps: testAssessor(time.Hour, time.Now()), ctl: ctl}
	row, findings := s.Evaluate(nil, time.Now(), IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil lifecycle should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil lifecycle should yield nil findings")
	}
}

func TestNilGuard_UnsafeRecurrence_NilControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})
	s := &unsafeRecurrenceStrategy{deps: testAssessor(time.Hour, base), ctl: nil}
	row, findings := s.Evaluate(tl, base, IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil control should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil control should yield nil findings")
	}
}

func TestNilGuard_UnsafeRecurrence_NilLifecycle(t *testing.T) {
	ctl := testControl("CTL.R.001", policy.TypeUnsafeRecurrence)
	s := &unsafeRecurrenceStrategy{deps: testAssessor(time.Hour, time.Now()), ctl: ctl}
	row, findings := s.Evaluate(nil, time.Now(), IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil lifecycle should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil lifecycle should yield nil findings")
	}
}

func TestNilGuard_PrefixExposure_NilControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})
	s := &prefixExposureStrategy{ctl: nil}
	row, findings := s.Evaluate(tl, base, IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil control should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil control should yield nil findings")
	}
}

func TestNilGuard_PrefixExposure_NilLifecycle(t *testing.T) {
	ctl := testControl("CTL.P.001", policy.TypePrefixExposure)
	s := &prefixExposureStrategy{ctl: ctl}
	row, findings := s.Evaluate(nil, time.Now(), IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil lifecycle should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil lifecycle should yield nil findings")
	}
}

func TestNilGuard_Unsupported_NilControl(t *testing.T) {
	s := &unsupportedStrategy{ctl: nil}
	row, findings := s.Evaluate(nil, time.Now(), IdentityIndex{})
	if row.ControlID != "" {
		t.Fatal("nil control should yield empty row")
	}
	if findings != nil {
		t.Fatal("nil control should yield nil findings")
	}
}

// --- validateCoverage ---

func TestValidateCoverage_MisconfiguredValidator(t *testing.T) {
	deps := testAssessor(0, time.Now())
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})
	reason, ok := validateCoverage(deps, tl, 0)
	if ok {
		t.Fatal("zero minSpan should make validator misconfigured → insufficient")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason for misconfigured validator")
	}
}

// --- unsafeRecurrenceStrategy disabled policy ---

func TestUnsafeRecurrenceStrategy_DisabledPolicy_ReturnsSkipped(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})

	ctl := testControl("CTL.REC.002", policy.TypeUnsafeRecurrence)
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(168*time.Hour, now), span: span}
	s := &unsafeRecurrenceStrategy{deps: deps, ctl: ctl}
	row, findings := s.Evaluate(tl, now, IdentityIndex{})
	if row.Verdict != evaluation.VerdictSkipped {
		t.Fatalf("disabled recurrence policy should skip, got %v", row.Verdict)
	}
	if len(findings) != 0 {
		t.Fatal("disabled recurrence policy should produce no findings")
	}
}

// --- emitViolationFinding confidence basis ---

func TestEmitViolationFinding_BasisCoverage_WhenMaxUnsafePositive(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(72 * time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(48 * time.Hour), true},
	})

	ctl := testControl("CTL.EMV.001", policy.TypeUnsafeState)
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(24*time.Hour, now), span: span}
	observation := newControlRow(ctl, tl)
	row, findings := emitViolationFinding(deps, ctl, tl, 24*time.Hour, now, IdentityIndex{}, observation)
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected VerdictViolation, got %v", row.Verdict)
	}
	if row.ConfidenceBasis != evaluation.BasisCoverage {
		t.Fatalf("expected BasisCoverage for positive maxUnsafe, got %q", row.ConfidenceBasis)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
}

func TestEmitViolationFinding_BasisPolicy_WhenMaxUnsafeZero(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(72 * time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(48 * time.Hour), true},
	})

	ctl := testControl("CTL.EMV.002", policy.TypeUnsafeState)
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(0, now), span: span}
	observation := newControlRow(ctl, tl)
	row, _ := emitViolationFinding(deps, ctl, tl, 0, now, IdentityIndex{}, observation)
	if row.ConfidenceBasis != evaluation.BasisPolicy {
		t.Fatalf("expected BasisPolicy for zero maxUnsafe, got %q", row.ConfidenceBasis)
	}
}

// =========================================================================
// collector.go — (48 survivors)
// =========================================================================

func TestStripeIndex_DeterministicSameID(t *testing.T) {
	a := stripeIndex("bucket-prod-1")
	b := stripeIndex("bucket-prod-1")
	if a != b {
		t.Fatalf("stripeIndex should be deterministic: %d != %d", a, b)
	}
}

func TestStripeIndex_WithinBounds(t *testing.T) {
	for _, id := range []string{"a", "b", "long-asset-id-12345", ""} {
		idx := stripeIndex(asset.ID(id))
		if idx < 0 || idx >= stripeCount {
			t.Fatalf("stripeIndex(%q) = %d, out of [0, %d)", id, idx, stripeCount)
		}
	}
}

func TestStripeIndex_DifferentIDsDifferentStripes(t *testing.T) {
	seen := map[int]bool{}
	ids := []string{"a", "b", "c", "d", "alpha", "beta", "gamma", "delta",
		"prod-1", "prod-2", "dev-1", "staging", "test-bucket-long-name"}
	for _, id := range ids {
		seen[stripeIndex(asset.ID(id))] = true
	}
	if len(seen) < 2 {
		t.Fatal("expected at least 2 distinct stripes from diverse IDs")
	}
}

func TestAssetRegistry_RegisterDedup(t *testing.T) {
	r := make(assetRegistry)
	if !r.register("a") {
		t.Fatal("first register should return true")
	}
	if r.register("a") {
		t.Fatal("second register should return false")
	}
	if !r.register("b") {
		t.Fatal("different id should return true")
	}
}

func TestRecordCheck_EmptyControlID_Dropped(t *testing.T) {
	c := NewCollector(10)
	c.RecordCheck(evaluation.ResourceCheck{})
	snap := c.Snapshot()
	if len(snap.Checks) != 0 {
		t.Fatalf("empty ControlID check should be dropped, got %d", len(snap.Checks))
	}
}

func TestRecordCheck_Valid_AppearsInSnapshot(t *testing.T) {
	c := NewCollector(10)
	c.RecordCheck(evaluation.ResourceCheck{ControlID: "CTL.A", AssetID: "a-1"})
	snap := c.Snapshot()
	if len(snap.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(snap.Checks))
	}
	if snap.Checks[0].ControlID != "CTL.A" {
		t.Fatalf("expected ControlID CTL.A, got %q", snap.Checks[0].ControlID)
	}
}

func TestRecordFindings_NilFindingSkipped(t *testing.T) {
	c := NewCollector(10)
	c.RecordFindings([]*evaluation.Finding{nil})
	snap := c.Snapshot()
	if len(snap.Findings) != 0 {
		t.Fatalf("nil finding should be skipped, got %d findings", len(snap.Findings))
	}
}

func TestRecordFindings_UnattributedFindingDropped(t *testing.T) {
	c := NewCollector(10)
	c.RecordFindings([]*evaluation.Finding{{FindingID: "f-1"}})
	snap := c.Snapshot()
	if len(snap.Findings) != 0 {
		t.Fatalf("unattributed finding (empty ControlID) should be skipped, got %d", len(snap.Findings))
	}
}

func TestRecordFindings_DuplicateSuppressed(t *testing.T) {
	c := NewCollector(10)
	f1 := &evaluation.Finding{FindingID: "f-1", ControlID: "CTL.A", AssetID: "a-1"}
	f2 := &evaluation.Finding{FindingID: "f-1", ControlID: "CTL.A", AssetID: "a-1"}
	c.RecordFindings([]*evaluation.Finding{f1})
	c.RecordFindings([]*evaluation.Finding{f2})
	snap := c.Snapshot()
	if len(snap.Findings) != 1 {
		t.Fatalf("duplicate finding should be suppressed, got %d", len(snap.Findings))
	}
}

func TestRecordFindings_EmptyFindingID_UsesFallback(t *testing.T) {
	c := NewCollector(10)
	f := &evaluation.Finding{ControlID: "CTL.A", AssetID: "a-1"}
	c.RecordFindings([]*evaluation.Finding{f})
	snap := c.Snapshot()
	if len(snap.Findings) != 1 {
		t.Fatalf("finding with empty FindingID should use fallback, got %d findings", len(snap.Findings))
	}
}

func TestRecordSkippedControl_AppearsInSnapshot(t *testing.T) {
	c := NewCollector(10)
	c.RecordSkippedControl("CTL.SKIP.001", "Skipped", "not evaluatable")
	snap := c.Snapshot()
	if len(snap.SkippedControls) != 1 {
		t.Fatalf("expected 1 skipped control, got %d", len(snap.SkippedControls))
	}
	if snap.SkippedControls[0].ControlID != "CTL.SKIP.001" {
		t.Fatalf("expected CTL.SKIP.001, got %q", snap.SkippedControls[0].ControlID)
	}
}

func TestRecordExemptedAsset_AppearsInSnapshot(t *testing.T) {
	c := NewCollector(10)
	c.RecordExemptedAsset("a-1", "a-*", "test exemption")
	snap := c.Snapshot()
	if len(snap.ExemptedAssets) != 1 {
		t.Fatalf("expected 1 exempted asset, got %d", len(snap.ExemptedAssets))
	}
	if snap.ExemptedAssets[0].Reason != "test exemption" {
		t.Fatalf("expected 'test exemption', got %q", snap.ExemptedAssets[0].Reason)
	}
}

func TestSnapshot_DeepClones_EvidenceSlices(t *testing.T) {
	c := NewCollector(10)
	f := &evaluation.Finding{
		FindingID: "f-1",
		ControlID: "CTL.A",
		AssetID:   "a-1",
		Evidence: evaluation.Evidence{
			Misconfigurations: []policy.Misconfiguration{{Property: predicate.NewFieldPath("p1")}},
			RootCauses:        []evaluation.RootCause{evaluation.RootCauseIdentity},
		},
	}
	c.RecordFindings([]*evaluation.Finding{f})
	snap := c.Snapshot()
	snap.Findings[0].Evidence.Misconfigurations = append(snap.Findings[0].Evidence.Misconfigurations, policy.Misconfiguration{Property: predicate.NewFieldPath("p2")})

	snap2 := c.Snapshot()
	if len(snap2.Findings[0].Evidence.Misconfigurations) != 1 {
		t.Fatal("Snapshot should deep-clone evidence; mutation of returned slice corrupted collector")
	}
}

func TestNewCollector_ZeroHint(t *testing.T) {
	c := NewCollector(0)
	if c == nil {
		t.Fatal("NewCollector(0) should not return nil")
	}
	if c.SeenAssetCount() != 0 {
		t.Fatal("new collector should have 0 seen assets")
	}
}

// =========================================================================
// lifecycles.go — (32 survivors)
// =========================================================================

func TestBuildLifecyclesPerControl_NilContextFallback(t *testing.T) {
	alwaysSafe := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	ctls := []policy.ControlDefinition{
		{ID: "CTL.L.001", Type: policy.TypeUnsafeState},
	}
	snaps := []asset.Snapshot{
		{CapturedAt: time.Now(), Assets: []asset.Asset{{ID: "a-1", Type: "s3_bucket"}}},
	}
	result, err := BuildLifecyclesPerControl(nil, ctls, snaps, alwaysSafe)
	if err != nil {
		t.Fatalf("nil context should use Background, got error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 control lifecycle map, got %d", len(result))
	}
}

func TestBuildLifecyclesPerControl_CancelledContextErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	alwaysSafe := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	ctls := []policy.ControlDefinition{
		{ID: "CTL.L.002", Type: policy.TypeUnsafeState},
	}
	snaps := []asset.Snapshot{
		{CapturedAt: time.Now(), Assets: []asset.Asset{{ID: "a-1", Type: "s3_bucket"}}},
	}
	_, err := BuildLifecyclesPerControl(ctx, ctls, snaps, alwaysSafe)
	if err == nil {
		t.Fatal("cancelled context should return error")
	}
}

func TestBuildLifecyclesPerControl_EmptySnapshots(t *testing.T) {
	alwaysSafe := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	ctls := []policy.ControlDefinition{{ID: "CTL.L.003", Type: policy.TypeUnsafeState}}
	result, err := BuildLifecyclesPerControl(context.Background(), ctls, nil, alwaysSafe)
	if err != nil {
		t.Fatalf("empty snapshots should not error: %v", err)
	}
	if len(result["CTL.L.003"]) != 0 {
		t.Fatal("empty snapshots should produce empty lifecycle map")
	}
}

func TestCheckUnsafe_NilCelEvalReturnsErr(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.CU.001"}
	a := asset.Asset{ID: "a-1"}
	snap := asset.Snapshot{}
	_, err := checkUnsafe(ctl, a, snap, nil)
	if err == nil {
		t.Fatal("nil celEval should return error")
	}
	if !errors.Is(err, ErrNilCELEvaluator) {
		t.Fatalf("expected ErrNilCELEvaluator, got %v", err)
	}
}

func TestCheckUnsafe_EvalError(t *testing.T) {
	failing := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, fmt.Errorf("boom")
	}
	ctl := &policy.ControlDefinition{ID: "CTL.CU.002"}
	a := asset.Asset{ID: "a-1"}
	snap := asset.Snapshot{}
	_, err := checkUnsafe(ctl, a, snap, failing)
	if err == nil {
		t.Fatal("failing eval should return error")
	}
}

func TestCheckUnsafe_Success(t *testing.T) {
	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	}
	ctl := &policy.ControlDefinition{ID: "CTL.CU.003"}
	a := asset.Asset{ID: "a-1"}
	snap := asset.Snapshot{}
	result, err := checkUnsafe(ctl, a, snap, eval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Fatal("expected true result")
	}
}

func TestControlVendorIndex_CacheHitConsistent(t *testing.T) {
	ctls := []policy.ControlDefinition{
		{ID: "CTL.V.001", ScopeTags: []kernel.ScopeTag{"aws"}},
		{ID: "CTL.V.002", ScopeTags: []kernel.ScopeTag{"gcp"}},
	}
	idx := buildControlVendorIndex(ctls)
	first := idx.controlsFor("aws", ctls)
	second := idx.controlsFor("aws", ctls)
	if len(first) != len(second) {
		t.Fatal("cache should return same results")
	}
}

func TestControlVendorIndex_ClonedResult(t *testing.T) {
	ctls := []policy.ControlDefinition{
		{ID: "CTL.V.001", ScopeTags: []kernel.ScopeTag{"aws"}},
	}
	idx := buildControlVendorIndex(ctls)
	result := idx.controlsFor("aws", ctls)
	if len(result) != 1 {
		t.Fatal("expected 1 control for aws")
	}
	result[0].ID = "MUTATED"
	second := idx.controlsFor("aws", ctls)
	if second[0].ID == "MUTATED" {
		t.Fatal("controlsFor must return a clone; mutation leaked into cache")
	}
}

// =========================================================================
// evidence_hook.go — (22 survivors)
// =========================================================================

func TestComplianceToMap_Nil(t *testing.T) {
	if got := complianceToMap(nil); got != nil {
		t.Fatalf("nil input should return nil, got %v", got)
	}
}

func TestComplianceToMap_NonEmpty(t *testing.T) {
	cm := policy.ComplianceMapping{
		policy.ComplianceFramework("CIS"): policy.RequirementID("1.1"),
	}
	result := complianceToMap(cm)
	if result["CIS"] != "1.1" {
		t.Fatalf("expected CIS=1.1, got %v", result)
	}
}

func TestLookupProperties_NilSnapshotReturnsNil(t *testing.T) {
	if got := lookupProperties(nil, "a-1"); got != nil {
		t.Fatalf("nil snapshot should return nil, got %v", got)
	}
}

func TestLookupProperties_MissingAsset(t *testing.T) {
	snap := &asset.Snapshot{Assets: []asset.Asset{{ID: "a-1"}}}
	if got := lookupProperties(snap, "a-2"); got != nil {
		t.Fatalf("missing asset should return nil, got %v", got)
	}
}

func TestLookupProperties_FoundAsset(t *testing.T) {
	props := map[string]any{"key": "val"}
	snap := &asset.Snapshot{Assets: []asset.Asset{{ID: "a-1", Properties: props}}}
	got := lookupProperties(snap, "a-1")
	if got["key"] != "val" {
		t.Fatalf("expected key=val, got %v", got)
	}
}

func TestIsSensitiveField_Sensitive(t *testing.T) {
	if !isSensitiveField("access_key") {
		t.Fatal("'access_key' should be sensitive")
	}
}

func TestIsSensitiveField_NotSensitive(t *testing.T) {
	if isSensitiveField("bucket_name") {
		t.Fatal("'bucket_name' should not be sensitive")
	}
}

func TestIsSensitiveField_Separators(t *testing.T) {
	for _, name := range []string{"secret-key", "secret_key", "SECRET.KEY"} {
		if !isSensitiveField(name) {
			t.Fatalf("expected %q to be sensitive", name)
		}
	}
}

func TestBuildEvidencePackage_SkipsNonCompliance(t *testing.T) {
	findings := []evaluation.Finding{{ControlID: "CTL.A", AssetID: "a-1"}}
	ctls := []policy.ControlDefinition{{ID: "CTL.A"}}
	pkg := buildEvidencePackage(findings, nil, ctls, nil, time.Now())
	if pkg == nil {
		t.Fatal("expected non-nil package")
	}
}

// =========================================================================
// finding_builder.go — (18 survivors)
// =========================================================================

func TestBorrowFinding_Zeroed(t *testing.T) {
	f := borrowFinding()
	if f == nil {
		t.Fatal("borrowFinding should not return nil")
	}
	if f.ControlID != "" {
		t.Fatalf("borrowed finding should be zeroed, got ControlID %q", f.ControlID)
	}
}

func TestReturnFindings_NilEntries(t *testing.T) {
	ReturnFindings([]*evaluation.Finding{nil, nil})
}

func TestReturnFindings_ValidEntries(t *testing.T) {
	f := borrowFinding()
	f.ControlID = "CTL.A"
	ReturnFindings([]*evaluation.Finding{f})
}

func TestNewBaseFinding_NilLifecycle(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.A", Name: "Test"}
	if f := newBaseFinding(ctl, nil); f != nil {
		t.Fatal("nil lifecycle should return nil finding")
	}
}

func TestNewBaseFinding_NilControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, false)
	if f := newBaseFinding(nil, tl); f != nil {
		t.Fatal("nil control should return nil finding")
	}
}

func TestNewBaseFinding_EmptyControlID(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, false)
	ctl := &policy.ControlDefinition{Name: "Test"}
	if f := newBaseFinding(ctl, tl); f != nil {
		t.Fatal("empty ControlID should return nil finding")
	}
}

func TestNewBaseFinding_HappyPath(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket", Vendor: "aws"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, true)
	ctl := &policy.ControlDefinition{ID: "CTL.FB.001", Name: "Test", Severity: policy.SeverityHigh}
	f := newBaseFinding(ctl, tl)
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.AssetID != "a-1" {
		t.Fatalf("expected AssetID a-1, got %q", f.AssetID)
	}
	if f.FindingID == "" {
		t.Fatal("expected non-empty FindingID")
	}
}

func TestNewFinding_NilLifecycleReturnsNil(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.A", Name: "Test"}
	f := NewFinding(ctl, nil, FindingContext{Reason: "test"})
	if f != nil {
		t.Fatal("nil lifecycle should return nil finding")
	}
}

func TestNewFinding_HappyPath(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, true)
	ctl := &policy.ControlDefinition{ID: "CTL.NF.001", Name: "Test", Severity: policy.SeverityHigh}
	f := NewFinding(ctl, tl, FindingContext{Reason: "exposed"})
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.TemporalRisk != "exposed" {
		t.Fatalf("expected TemporalRisk 'exposed', got %q", f.Evidence.TemporalRisk)
	}
}

// =========================================================================
// coverage.go — (17 survivors)
// =========================================================================

func TestCoverageValidator_ZeroMinSpan(t *testing.T) {
	_, err := NewCoverageValidator(0, time.Hour)
	if err == nil {
		t.Fatal("zero minSpan should error")
	}
}

func TestCoverageValidator_NegativeMinSpan(t *testing.T) {
	_, err := NewCoverageValidator(-time.Hour, time.Hour)
	if err == nil {
		t.Fatal("negative minSpan should error")
	}
}

func TestCoverageValidator_MinSpanLessThanMaxGap(t *testing.T) {
	_, err := NewCoverageValidator(time.Hour, 2*time.Hour)
	if err == nil {
		t.Fatal("minSpan < maxGap should error")
	}
}

func TestCoverageValidator_MinSpanEqualsMaxGap(t *testing.T) {
	v, err := NewCoverageValidator(time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("minSpan == maxGap should be valid: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestCoverageValidator_MaxGapZero(t *testing.T) {
	v, err := NewCoverageValidator(time.Hour, 0)
	if err != nil {
		t.Fatalf("zero maxGap should be valid: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestIsSufficient_NilLifecycleInsufficient(t *testing.T) {
	v, _ := NewCoverageValidator(time.Hour, 0)
	reason, ok := v.IsSufficient(nil)
	if ok {
		t.Fatal("nil lifecycle should be insufficient")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestIsSufficient_ShortSpan(t *testing.T) {
	v, _ := NewCoverageValidator(48*time.Hour, 0)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
		{base.Add(time.Hour), false},
	})
	reason, ok := v.IsSufficient(tl)
	if ok {
		t.Fatal("1-hour span should be insufficient for 48h requirement")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason for short span")
	}
}

func TestIsSufficient_Sufficient(t *testing.T) {
	v, _ := NewCoverageValidator(2*time.Hour, 0)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
		{base.Add(time.Hour), false},
		{base.Add(3 * time.Hour), false},
	})
	_, ok := v.IsSufficient(tl)
	if !ok {
		t.Fatal("3-hour span should be sufficient for 2h requirement")
	}
}

// =========================================================================
// finding_gen.go — (14 survivors)
// =========================================================================

func TestDeriveRootCauses_Empty(t *testing.T) {
	if got := DeriveRootCauses(nil); got != nil {
		t.Fatalf("empty input should return nil, got %v", got)
	}
}

func TestDeriveRootCauses_IdentityOnly(t *testing.T) {
	mcs := []policy.Misconfiguration{{Category: policy.CategoryIdentity}}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseIdentity {
		t.Fatalf("expected [RootCauseIdentity], got %v", causes)
	}
}

func TestDeriveRootCauses_ResourceOnly(t *testing.T) {
	mcs := []policy.Misconfiguration{{Category: policy.CategoryResource}}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseResource {
		t.Fatalf("expected [RootCauseResource], got %v", causes)
	}
}

func TestDeriveRootCauses_BothOrdered(t *testing.T) {
	mcs := []policy.Misconfiguration{
		{Category: policy.CategoryResource},
		{Category: policy.CategoryIdentity},
	}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 2 {
		t.Fatalf("expected 2 causes, got %d", len(causes))
	}
	if causes[0] != evaluation.RootCauseIdentity {
		t.Fatal("identity should come before resource")
	}
	if causes[1] != evaluation.RootCauseResource {
		t.Fatal("resource should come second")
	}
}

func TestDeriveRootCauses_Uncategorized(t *testing.T) {
	mcs := []policy.Misconfiguration{{Category: policy.CategoryUnknown}}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseGeneral {
		t.Fatalf("uncategorized should map to General, got %v", causes)
	}
}

func TestExtractSourceEvidence_EmptyCausesReturnsNil(t *testing.T) {
	a := asset.Asset{ID: "a"}
	if got := ExtractSourceEvidence(a, nil); got != nil {
		t.Fatalf("empty causes should return nil, got %v", got)
	}
}

func TestToSorted_Nil(t *testing.T) {
	if got := toSorted[kernel.StatementID](nil); got != nil {
		t.Fatalf("nil input should return nil, got %v", got)
	}
}

func TestToSorted_SortsAndConvertsTypes(t *testing.T) {
	result := toSorted[kernel.StatementID]([]string{"c", "a", "b"})
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
	if result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Fatalf("expected [a b c], got %v", result)
	}
}

func TestCreateDurationFinding_NilLifecycleReturnsNilAndErr(t *testing.T) {
	f, err := CreateDurationFinding(DurationFindingInput{
		Control: &policy.ControlDefinition{ID: "CTL.DF.001"},
	})
	if f != nil {
		t.Fatal("nil lifecycle should return nil finding")
	}
	if err == nil {
		t.Fatal("nil lifecycle should return error")
	}
}

func TestCreateDurationFinding_NilControlReturnsNilAndErr(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, true)
	f, err := CreateDurationFinding(DurationFindingInput{
		ExposureLifecycle: tl,
	})
	if f != nil {
		t.Fatal("nil control should return nil finding")
	}
	if err == nil {
		t.Fatal("nil control should return error")
	}
}

// =========================================================================
// recurrence.go — (10 survivors)
// =========================================================================

func TestCreateRecurrenceFinding_NilControlReturnsNil(t *testing.T) {
	if f := CreateRecurrenceFinding(nil, nil, RecurrenceStats{}); f != nil {
		t.Fatal("nil control should return nil")
	}
}

func TestCreateRecurrenceFinding_NilLifecycleReturnsNil(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.RF.001", Name: "Test", Severity: policy.SeverityHigh}
	if f := CreateRecurrenceFinding(nil, ctl, RecurrenceStats{}); f != nil {
		t.Fatal("nil lifecycle should return nil")
	}
}

func TestCreateRecurrenceFinding_HappyPath(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, true)

	ctl := &policy.ControlDefinition{
		ID:       "CTL.RF.002",
		Name:     "Test",
		Severity: policy.SeverityHigh,
		Params:   policy.NewParams(map[string]any{"recurrence_threshold": 3, "window_days": 7}),
	}
	stats := RecurrenceStats{Count: 5, First: base, Last: base.Add(48 * time.Hour)}
	f := CreateRecurrenceFinding(tl, ctl, stats)
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.ExposureWindowCount != 5 {
		t.Fatalf("expected ExposureWindowCount 5, got %d", f.Evidence.ExposureWindowCount)
	}
	if f.Evidence.RecurrenceThreshold != 3 {
		t.Fatalf("expected RecurrenceThreshold 3, got %d", f.Evidence.RecurrenceThreshold)
	}
}

func TestEvaluateRecurrenceForControl_DisabledPolicy(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, true)

	ctl := &policy.ControlDefinition{ID: "CTL.ER.001"}
	findings := EvaluateRecurrenceForControl(tl, ctl, base.Add(time.Hour), IdentityIndex{})
	if findings != nil {
		t.Fatal("disabled policy should return nil findings")
	}
}

func TestEvaluateRecurrenceForControl_BelowThreshold(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, true)
	_ = tl.RecordCheck(base.Add(time.Hour), false)

	ctl := &policy.ControlDefinition{
		ID:     "CTL.ER.002",
		Params: policy.NewParams(map[string]any{"recurrence_threshold": 10, "window_days": 30}),
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	findings := EvaluateRecurrenceForControl(tl, ctl, base.Add(2*time.Hour), IdentityIndex{})
	if findings != nil {
		t.Fatal("below-threshold should return nil findings")
	}
}

// =========================================================================
// exposure.go — (15 survivors)
// =========================================================================

func TestNewPrefixExposureRow_NilLifecycle(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "CTL.PE.001"}
	row := newPrefixExposureRow(nil, ctl)
	if row.ControlID != "" {
		t.Fatal("nil lifecycle should produce empty row")
	}
}

func TestNewPrefixExposureRow_NilControl(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})
	row := newPrefixExposureRow(tl, nil)
	if row.ControlID != "" {
		t.Fatal("nil control should produce empty row")
	}
}

func TestNewPrefixExposureRow_HappyPath(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{{base, false}})
	ctl := &policy.ControlDefinition{ID: "CTL.PE.002"}
	row := newPrefixExposureRow(tl, ctl)
	if row.ControlID != "CTL.PE.002" {
		t.Fatalf("expected ControlID CTL.PE.002, got %q", row.ControlID)
	}
	if row.Verdict != evaluation.VerdictPass {
		t.Fatalf("expected initial VerdictPass, got %v", row.Verdict)
	}
}

func TestMsgMissingProtectedPrefixes_NonEmpty(t *testing.T) {
	msg := msgMissingProtectedPrefixes()
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
}

// =========================================================================
// Supplemental: unsafeDurationStrategy pass with coverage
// =========================================================================

func TestUnsafeDurationStrategy_Pass_WithSufficientCoverage(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(24 * time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
		{base.Add(6 * time.Hour), false},
		{base.Add(12 * time.Hour), false},
	})
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(4*time.Hour, now), span: span}
	ctl := testControl("CTL.DUR.PASS", policy.TypeUnsafeDuration)
	s := &unsafeDurationStrategy{deps: deps, ctl: ctl}
	row, findings := s.Evaluate(tl, now, IdentityIndex{})
	if row.Verdict != evaluation.VerdictPass {
		t.Fatalf("expected VerdictPass, got %v", row.Verdict)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// =========================================================================
// Supplemental: unsafeStateStrategy violation path
// =========================================================================

func TestUnsafeStateStrategy_Violation(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(72 * time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(48 * time.Hour), true},
	})
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(24*time.Hour, now), span: span}
	ctl := testControl("CTL.STATE.VIO", policy.TypeUnsafeState)
	ctl.Params = policy.NewParams(map[string]any{"max_unsafe_duration": "24h"})
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	s := &unsafeStateStrategy{deps: deps, ctl: ctl}
	row, findings := s.Evaluate(tl, now, IdentityIndex{})
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected VerdictViolation, got %v", row.Verdict)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
}

// --- unsafeStateStrategy: zero-threshold immediate violation ---

func TestUnsafeStateStrategy_ZeroThreshold_ImmediateViolation(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(2 * time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(time.Hour), true},
	})
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(0, now), span: span}
	ctl := testControl("CTL.STATE.ZERO", policy.TypeUnsafeState)
	s := &unsafeStateStrategy{deps: deps, ctl: ctl}
	row, findings := s.Evaluate(tl, now, IdentityIndex{})
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("zero-threshold unsafe_state should violate immediately, got %v", row.Verdict)
	}
	if len(findings) == 0 {
		t.Fatal("expected violation finding")
	}
}

// --- unsafeDurationStrategy: violation path ---

func TestUnsafeDurationStrategy_Violation(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(72 * time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(48 * time.Hour), true},
	})
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(24*time.Hour, now), span: span}
	ctl := testControl("CTL.DUR.VIO", policy.TypeUnsafeDuration)
	s := &unsafeDurationStrategy{deps: deps, ctl: ctl}
	row, findings := s.Evaluate(tl, now, IdentityIndex{})
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected VerdictViolation, got %v", row.Verdict)
	}
	if len(findings) == 0 {
		t.Fatal("expected violation finding")
	}
}

// --- unsafeDurationStrategy: threshold error ---

func TestUnsafeDurationStrategy_InsufficientCoverage(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)
	tl := buildLifecycle(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
	})
	span := &recordingSpan{}
	deps := &stubDeps{Assessor: testAssessor(48*time.Hour, now), span: span}
	ctl := testControl("CTL.DUR.INC", policy.TypeUnsafeDuration)
	s := &unsafeDurationStrategy{deps: deps, ctl: ctl}
	row, _ := s.Evaluate(tl, now, IdentityIndex{})
	if row.Verdict != evaluation.VerdictInconclusive {
		t.Fatalf("expected VerdictInconclusive for insufficient coverage, got %v", row.Verdict)
	}
}

// =========================================================================
// Supplemental: unused variable guards for ports import
// =========================================================================

var _ ports.Clock = stubClock{}
