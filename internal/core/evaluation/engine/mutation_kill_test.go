package engine

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// --- Cluster 1: WithX option setters (assessor.go:64-113) ---

func TestWithClock_WiresField(t *testing.T) {
	clk := stubClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	a := NewAssessor(WithClock(clk))
	if a.clock != clk {
		t.Fatal("WithClock did not set clock")
	}
}

func TestWithPredicateEval_WiresField(t *testing.T) {
	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	}
	a := NewAssessor(WithPredicateEval(eval))
	if a.predicateEval == nil {
		t.Fatal("WithPredicateEval did not set predicateEval")
	}
}

func TestWithPredicateParser_WiresField(t *testing.T) {
	parser := func(_ any) (*policy.UnsafePredicate, error) {
		return &policy.UnsafePredicate{}, nil
	}
	a := NewAssessor(WithPredicateParser(parser))
	if a.predicateParser == nil {
		t.Fatal("WithPredicateParser did not set predicateParser")
	}
}

func TestWithSLAThreshold_WiresField(t *testing.T) {
	a := NewAssessor(WithSLAThreshold(72 * time.Hour))
	if a.governance.slaThreshold != 72*time.Hour {
		t.Fatalf("expected 72h, got %v", a.governance.slaThreshold)
	}
}

func TestWithControls_WiresField(t *testing.T) {
	ctls := []policy.ControlDefinition{
		{ID: "CTL.T.001", Name: "test"},
	}
	a := NewAssessor(WithControls(ctls))
	if len(a.controls) != 1 || a.controls[0].ID != "CTL.T.001" {
		t.Fatal("WithControls did not set controls")
	}
}

func TestWithExemptions_WiresField(t *testing.T) {
	e := policy.NewExemptionConfig("", nil)
	a := NewAssessor(WithExemptions(e))
	if a.exemptions != e {
		t.Fatal("WithExemptions did not set exemptions")
	}
}

func TestWithExceptions_WiresField(t *testing.T) {
	e := policy.NewExceptionConfig(nil)
	a := NewAssessor(WithExceptions(e))
	if a.exceptions != e {
		t.Fatal("WithExceptions did not set exceptions")
	}
}

func TestWithAcknowledgments_WiresField(t *testing.T) {
	ack := policy.NewAcknowledgmentConfig(nil)
	a := NewAssessor(WithAcknowledgments(ack))
	if a.acknowledgments != ack {
		t.Fatal("WithAcknowledgments did not set acknowledgments")
	}
}

func TestWithConfidence_WiresField(t *testing.T) {
	custom := evaluation.ConfidenceCalculator{HighMultiplier: 1, MedMultiplier: 1}
	a := NewAssessor(WithConfidence(custom))
	got := a.governance.confidence.Derive(time.Hour, 2*time.Hour)
	if got != evaluation.ConfidenceHigh {
		t.Fatalf("expected ConfidenceHigh from custom calculator, got %v", got)
	}
}

func TestWithTracer_WiresField(t *testing.T) {
	a := NewAssessor(WithTracer(nil))
	if a.tracer != nil {
		t.Fatal("WithTracer(nil) should set tracer to nil")
	}
}

// --- Cluster 2: Assess() precondition guards (assessor.go:305-321) ---

func TestAssess_NilContext(t *testing.T) {
	a := newTestAssessor().build()
	//nolint:staticcheck // SA1012: intentionally passing nil context to test guard
	_, err := a.Assess(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestAssess_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := newTestAssessor().build()
	_, err := a.Assess(ctx, nil)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestAssess_NilClock(t *testing.T) {
	a := NewAssessor(
		WithPredicateEval(func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return false, nil
		}),
		WithPredicateParser(func(_ any) (*policy.UnsafePredicate, error) {
			return &policy.UnsafePredicate{}, nil
		}),
	)
	_, err := a.Assess(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil clock")
	}
}

func TestAssess_NilPredicateEval(t *testing.T) {
	a := NewAssessor(
		WithClock(stubClock{t: time.Now()}),
		WithPredicateParser(func(_ any) (*policy.UnsafePredicate, error) {
			return &policy.UnsafePredicate{}, nil
		}),
	)
	_, err := a.Assess(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil predicateEval")
	}
}

func TestAssess_NilPredicateParser(t *testing.T) {
	a := NewAssessor(
		WithClock(stubClock{t: time.Now()}),
		WithPredicateEval(func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return false, nil
		}),
	)
	_, err := a.Assess(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil predicateParser")
	}
}

// --- Cluster 3: controlTimeout env override (assessor.go:385-388) ---

func TestAssess_ControlTimeoutEnvOverride(t *testing.T) {
	t.Setenv("STAVE_CONTROL_EVAL_TIMEOUT", "30s")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary.TotalAssets != 1 {
		t.Fatalf("expected 1 total asset, got %d", result.Summary.TotalAssets)
	}
}

func TestAssess_ControlTimeoutInvalidEnv(t *testing.T) {
	t.Setenv("STAVE_CONTROL_EVAL_TIMEOUT", "not-a-duration")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	_, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("invalid env should fall back to default, got error: %v", err)
	}
}

// --- Cluster 5: Exemption with nil lifecycle (assessor.go:495-502) ---

func TestAssess_ExemptedAssetRecordsCheck(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()

	exemptions := policy.NewExemptionConfig("", []policy.ExemptionRule{
		{Pattern: "bucket-*", Reason: "test exemption"},
	})

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()
	a.exemptions = exemptions

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ExemptedAssets) == 0 {
		t.Fatal("expected exempted asset to be recorded")
	}
	if result.ExemptedAssets[0].Reason != "test exemption" {
		t.Fatalf("expected reason 'test exemption', got %q", result.ExemptedAssets[0].Reason)
	}
}

// --- Cluster 6: compileReport sort ordering (assessor.go:581-583) ---

func TestCompileReport_ChecksSortedByControlThenAsset(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl1 := newTestControl("CTL.B.001").typed(policy.TypeUnsafeState).build()
	ctl2 := newTestControl("CTL.A.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(48*time.Hour)).
		withControls(ctl1, ctl2).
		alwaysSafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "z-bucket", "a-bucket").
		at(48*time.Hour, "z-bucket", "a-bucket").
		build()

	result, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Checks) < 2 {
		t.Fatalf("expected at least 2 checks, got %d", len(result.Checks))
	}
	for i := 1; i < len(result.Checks); i++ {
		prev := result.Checks[i-1]
		curr := result.Checks[i]
		if prev.ControlID > curr.ControlID {
			t.Errorf("checks not sorted by ControlID: %s > %s", prev.ControlID, curr.ControlID)
		}
		if prev.ControlID == curr.ControlID && prev.AssetID > curr.AssetID {
			t.Errorf("checks not sorted by AssetID within control: %s > %s", prev.AssetID, curr.AssetID)
		}
	}
}

// --- Cluster 7: Evidence generation (assessor.go:666) ---

func TestCompileReport_GenerateEvidence(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withSLA(1 * time.Hour).
		withControls(ctl).
		alwaysUnsafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps, AssessmentOptions{
		GenerateEvidence: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.EvidencePackage == nil {
		t.Fatal("expected non-nil EvidencePackage when GenerateEvidence=true")
	}
}

func TestCompileReport_NoEvidenceByDefault(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withSLA(1 * time.Hour).
		withControls(ctl).
		alwaysUnsafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.EvidencePackage != nil {
		t.Fatal("expected nil EvidencePackage when GenerateEvidence=false")
	}
}

// --- Cluster 8: buildSuppressionSet (assessor.go:790-795) ---

func TestBuildSuppressionSet_ExcludesInvalidAcks(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A", AssetID: "asset-1",
			Status: evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:  "acknowledgment",
				Valid: true,
			},
		},
		{
			ControlID: "CTL.B", AssetID: "asset-2",
			Status: evaluation.FindingSuppressed,
			Suppression: &evaluation.Suppression{
				Kind:          "acknowledgment",
				Valid:         false,
				InvalidReason: "expired",
			},
		},
		{
			ControlID: "CTL.C", AssetID: "asset-3",
			Status: evaluation.FindingActive,
		},
	}

	set := buildSuppressionSet(findings)
	if len(set) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(set))
	}
	if _, ok := set[risk.SuppressionKey{ControlID: "CTL.A", AssetID: "asset-1"}]; !ok {
		t.Error("valid suppressed finding should be in the set")
	}
	if _, ok := set[risk.SuppressionKey{ControlID: "CTL.B", AssetID: "asset-2"}]; ok {
		t.Error("invalid suppressed finding should NOT be in the set")
	}
}

// --- Cluster 9: Acknowledgment expired / compensating-control paths ---

func TestApplyAcknowledgments_ExpiredAck(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:      "CTL.X",
			AssetID:        "asset-A",
			Rationale:      "accepted risk",
			AcknowledgedBy: "ops@example.com",
			ExpiryDate:     "2026-01-01",
		},
	})

	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.X", AssetID: "asset-A"},
	}

	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": {}},
	}

	result := applyAcknowledgments(findings, nil, acks, now, coverage)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Suppression == nil {
		t.Fatal("expected suppression on expired ack")
	}
	if result[0].Suppression.Valid {
		t.Error("expired ack should be marked invalid")
	}
	if result[0].Suppression.InvalidReason != "expired" {
		t.Errorf("expected reason 'expired', got %q", result[0].Suppression.InvalidReason)
	}
}

func TestApplyAcknowledgments_CompensatingControlFailing(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.X",
			AssetID:              "asset-A",
			Rationale:            "compensated",
			AcknowledgedBy:       "ops@example.com",
			CompensatingControls: []kernel.ControlID{"CTL.Y"},
		},
	})

	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.X", AssetID: "asset-A"},
		{FindingID: "f2", ControlID: "CTL.Y", AssetID: "asset-A"},
	}

	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": {}, "CTL.Y": {}},
	}

	result := applyAcknowledgments(findings, nil, acks, now, coverage)

	var xFinding *evaluation.Finding
	for i := range result {
		if result[i].ControlID == "CTL.X" {
			xFinding = &result[i]
			break
		}
	}
	if xFinding == nil {
		t.Fatal("CTL.X finding missing from results")
	}
	if xFinding.Suppression == nil {
		t.Fatal("expected suppression when compensating control fails")
	}
	if xFinding.Suppression.Valid {
		t.Error("ack should be invalid when compensating control fails")
	}
	if xFinding.Suppression.InvalidReason != "compensating_controls_failing" {
		t.Errorf("expected reason 'compensating_controls_failing', got %q", xFinding.Suppression.InvalidReason)
	}
}

func TestApplyAcknowledgments_CompensatingControlExcepted(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.X",
			AssetID:              "asset-A",
			Rationale:            "compensated",
			AcknowledgedBy:       "ops@example.com",
			CompensatingControls: []kernel.ControlID{"CTL.Y"},
		},
	})

	activeFindings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.X", AssetID: "asset-A"},
	}
	exceptedFindings := []evaluation.Finding{
		{FindingID: "f2", ControlID: "CTL.Y", AssetID: "asset-A"},
	}

	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": {}, "CTL.Y": {}},
	}

	result := applyAcknowledgments(activeFindings, exceptedFindings, acks, now, coverage)

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Suppression == nil {
		t.Fatal("expected suppression when compensating control is excepted")
	}
	if result[0].Suppression.Valid {
		t.Error("ack should be invalid when compensating control is excepted")
	}
}

func TestApplyAcknowledgments_CompensatingControlUnevaluated(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.X",
			AssetID:              "asset-A",
			Rationale:            "compensated",
			AcknowledgedBy:       "ops@example.com",
			CompensatingControls: []kernel.ControlID{"CTL.Y"},
		},
	})

	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.X", AssetID: "asset-A"},
	}

	// CTL.Y never evaluated for asset-A
	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": {}},
	}

	result := applyAcknowledgments(findings, nil, acks, now, coverage)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Suppression == nil {
		t.Fatal("expected suppression when compensating control unevaluated")
	}
	if result[0].Suppression.Valid {
		t.Error("ack should be invalid when compensating control was never evaluated")
	}
}

func TestApplyAcknowledgments_NilConfig(t *testing.T) {
	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.X", AssetID: "asset-A"},
	}
	result := applyAcknowledgments(findings, nil, nil, time.Now(), nil)
	if len(result) != 1 {
		t.Fatalf("nil acks should return findings unchanged, got %d", len(result))
	}
	if result[0].Status == evaluation.FindingSuppressed {
		t.Error("nil acks should not suppress anything")
	}
}

// --- Cluster 11: Collector dedup ---

func TestCollector_RecordExemption_FirstCallReturnsTrue(t *testing.T) {
	c := NewCollector(10)
	if !c.RecordExemption("asset-1") {
		t.Error("first RecordExemption should return true")
	}
	if c.RecordExemption("asset-1") {
		t.Error("second RecordExemption for same asset should return false")
	}
}

func TestCollector_SeenAssetCount(t *testing.T) {
	c := NewCollector(10)
	c.RecordSeenAsset("a")
	c.RecordSeenAsset("b")
	c.RecordSeenAsset("a") // duplicate
	if got := c.SeenAssetCount(); got != 2 {
		t.Fatalf("expected 2 unique seen assets, got %d", got)
	}
}

func TestCollector_NonCompliantAssetCount(t *testing.T) {
	c := NewCollector(10)
	c.RecordNonCompliantAsset("a")
	c.RecordNonCompliantAsset("b")
	c.RecordNonCompliantAsset("a") // duplicate
	if got := c.NonCompliantAssetCount(); got != 2 {
		t.Fatalf("expected 2 unique non-compliant assets, got %d", got)
	}
}

// --- EvaluationCoverage ---

func TestEvaluationCoverage_NilMap(t *testing.T) {
	var c EvaluationCoverage
	if c.Contains("asset-1", "CTL.X") {
		t.Error("nil coverage should return false")
	}
}

func TestEvaluationCoverage_MissingAsset(t *testing.T) {
	c := EvaluationCoverage{
		"asset-1": {"CTL.X": {}},
	}
	if c.Contains("asset-missing", "CTL.X") {
		t.Error("missing asset should return false")
	}
}

func TestEvaluationCoverage_MissingControl(t *testing.T) {
	c := EvaluationCoverage{
		"asset-1": {"CTL.X": {}},
	}
	if c.Contains("asset-1", "CTL.MISSING") {
		t.Error("missing control should return false")
	}
}

// --- partitionIndeterminateFindings ---

func TestPartitionIndeterminateFindings_SetsDataQuality(t *testing.T) {
	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"},
	}
	confirmed, indeterminate := partitionIndeterminateFindings(findings)
	if len(confirmed) != 1 {
		t.Fatalf("non-indeterminate finding should be confirmed, got %d confirmed", len(confirmed))
	}
	if confirmed[0].DataQuality != evaluation.DataQualityConfirmed {
		t.Errorf("expected DataQualityConfirmed, got %v", confirmed[0].DataQuality)
	}
	if len(indeterminate) != 0 {
		t.Errorf("expected 0 indeterminate, got %d", len(indeterminate))
	}
}

// --- Logger nil-safety (assessor.go:172) ---

func TestAssessor_Logger_NilReceiver(t *testing.T) {
	var a *Assessor
	logger := a.Logger()
	if logger == nil {
		t.Fatal("Logger on nil Assessor should return slog.Default()")
	}
}

func TestAssessor_Logger_NilLoggerField(t *testing.T) {
	a := &Assessor{}
	logger := a.Logger()
	if logger == nil {
		t.Fatal("Logger with nil logger field should return slog.Default()")
	}
}

// --- assetHint max computation (assessor.go:350-353) ---

func TestAssess_MultipleSnapshotsDifferentAssetCounts(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()

	a := newTestAssessor().
		withClock(base.Add(72 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()

	// First snapshot: 1 asset. Second: 3 assets (should pick max=3 for hint)
	snaps := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets:     []asset.Asset{{ID: "a", Type: "s3_bucket"}},
		},
		{
			CapturedAt: base.Add(48 * time.Hour),
			Assets: []asset.Asset{
				{ID: "a", Type: "s3_bucket"},
				{ID: "b", Type: "s3_bucket"},
				{ID: "c", Type: "s3_bucket"},
			},
		},
	}

	result, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary.TotalAssets != 3 {
		t.Fatalf("expected 3 total assets, got %d", result.Summary.TotalAssets)
	}
}

// --- Skipped (non-evaluatable) controls ---

func TestAssess_SkippedControlRecorded(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// TypeUnknown is not evaluatable
	ctl := policy.ControlDefinition{
		ID:   "CTL.SKIP.001",
		Name: "Skippable",
		Type: policy.TypeUnknown,
	}

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
		build()

	snaps := newLifecycleBuilder(base).
		at(0, "bucket-1").
		at(48*time.Hour, "bucket-1").
		build()

	result, err := a.Assess(context.Background(), snaps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.SkippedControls) == 0 {
		t.Fatal("expected skipped control to be recorded")
	}
}

// --- hasEmptyPolicy / canComputeDigests ---

func TestHasEmptyPolicy(t *testing.T) {
	a := NewAssessor()
	if !a.hasEmptyPolicy() {
		t.Error("empty assessor should have empty policy")
	}
	a.controls = []policy.ControlDefinition{{ID: "CTL.A"}}
	if a.hasEmptyPolicy() {
		t.Error("assessor with controls should not have empty policy")
	}
}

func TestCanComputeDigests(t *testing.T) {
	a := NewAssessor()
	if a.canComputeDigests() {
		t.Error("assessor without hasher should not compute digests")
	}
}
