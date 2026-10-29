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
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
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

// --- Cluster 12: Key isolation enrichment (key_isolation.go) ---

func TestParseSensitivity_Ordering(t *testing.T) {
	if SensitivityPHI <= SensitivityConfidential {
		t.Error("PHI must be > Confidential")
	}
	if SensitivityConfidential <= SensitivityInternal {
		t.Error("Confidential must be > Internal")
	}
	if SensitivityInternal <= SensitivityPublic {
		t.Error("Internal must be > Public")
	}
	if SensitivityPublic <= SensitivityUnclassified {
		t.Error("Public must be > Unclassified")
	}
}

func TestExtractClassification_TopLevelTags(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"tags": map[string]any{"data-classification": "phi"},
	}}
	if got := extractClassification(a); got != "phi" {
		t.Fatalf("expected 'phi', got %q", got)
	}
}

func TestExtractClassification_StorageTagsDataUnderscore(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"storage": map[string]any{
			"tags": map[string]any{"data_classification": "confidential"},
		},
	}}
	if got := extractClassification(a); got != "confidential" {
		t.Fatalf("expected 'confidential', got %q", got)
	}
}

func TestExtractClassification_StorageTagsCamelCase(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"storage": map[string]any{
			"tags": map[string]any{"DataClassification": "Internal"},
		},
	}}
	if got := extractClassification(a); got != "internal" {
		t.Fatalf("expected 'internal', got %q", got)
	}
}

func TestExtractClassification_BadTagsType(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"tags": "not-a-map",
	}}
	if got := extractClassification(a); got != "unclassified" {
		t.Fatalf("expected 'unclassified' for bad tags type, got %q", got)
	}
}

func TestExtractClassification_BadStorageTagsType(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"storage": map[string]any{
			"tags": []string{"not", "a", "map"},
		},
	}}
	if got := extractClassification(a); got != "unclassified" {
		t.Fatalf("expected 'unclassified' for bad storage.tags type, got %q", got)
	}
}

func TestExtractClassification_NoTagsAnywhere(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"storage": map[string]any{"encryption": true},
	}}
	if got := extractClassification(a); got != "unclassified" {
		t.Fatalf("expected 'unclassified', got %q", got)
	}
}

func TestExtractClassification_EmptyTagValue(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"tags": map[string]any{"data-classification": ""},
	}}
	if got := extractClassification(a); got != "unclassified" {
		t.Fatalf("expected 'unclassified' for empty tag value, got %q", got)
	}
}

func TestGetOrCreateMap_ExistingCloned(t *testing.T) {
	original := map[string]any{"nested": "val"}
	m := map[string]any{"crypto": original}
	result := getOrCreateMap(m, "crypto")
	if result["nested"] != "val" {
		t.Fatal("existing value should be present in clone")
	}
	result["new_key"] = "new_val"
	if _, ok := original["new_key"]; ok {
		t.Fatal("getOrCreateMap must clone the existing map, not return it")
	}
}

func TestGetOrCreateMap_MissingCreatesNew(t *testing.T) {
	m := map[string]any{}
	result := getOrCreateMap(m, "crypto")
	if result == nil {
		t.Fatal("expected new map created")
	}
	result["key"] = "val"
	inner, ok := m["crypto"].(map[string]any)
	if !ok || inner["key"] != "val" {
		t.Fatal("new map should be stored under the key in parent")
	}
}

func TestToLowerTrim_AlreadyLower(t *testing.T) {
	if got := toLowerTrim("hello"); got != "hello" {
		t.Fatalf("expected 'hello', got %q", got)
	}
}

func TestToLowerTrim_NeedsLowering(t *testing.T) {
	if got := toLowerTrim("HELLO"); got != "hello" {
		t.Fatalf("expected 'hello', got %q", got)
	}
}

func TestToLowerTrim_Whitespace(t *testing.T) {
	if got := toLowerTrim("  PHI  "); got != "phi" {
		t.Fatalf("expected 'phi', got %q", got)
	}
}

func TestToLowerTrim_Empty(t *testing.T) {
	if got := toLowerTrim(""); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestCloneAssetProperties_NilProperties(t *testing.T) {
	a := asset.Asset{ID: "a"}
	cloned := cloneAssetProperties(a)
	if cloned.Properties != nil {
		t.Fatal("nil properties should stay nil after clone")
	}
}

func TestCloneAssetProperties_IndependentCopy(t *testing.T) {
	original := map[string]any{"key": "val"}
	a := asset.Asset{ID: "a", Properties: original}
	cloned := cloneAssetProperties(a)
	cloned.Properties["new"] = "added"
	if _, ok := original["new"]; ok {
		t.Fatal("clone must not share backing map with original")
	}
}

func TestEnrichKeyIsolation_EmptySnapshots(t *testing.T) {
	result := EnrichKeyIsolation(nil)
	if len(result) != 0 {
		t.Fatal("nil snapshots should return empty slice")
	}
	result = EnrichKeyIsolation([]asset.Snapshot{})
	if len(result) != 0 {
		t.Fatal("empty snapshots should return empty slice")
	}
}

func TestEnrichKeyIsolation_NoKMSKeys_ClonesAssets(t *testing.T) {
	orig := asset.Asset{ID: "a", Type: "s3_bucket", Properties: map[string]any{"foo": "bar"}}
	snaps := []asset.Snapshot{{Assets: []asset.Asset{orig}}}
	enriched := EnrichKeyIsolation(snaps)

	enriched[0].Assets[0].Properties["injected"] = true
	if _, ok := orig.Properties["injected"]; ok {
		t.Fatal("EnrichKeyIsolation must clone even when no KMS keys are present")
	}
}

func TestEnrichKeyIsolation_ExclusiveKey(t *testing.T) {
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{
			makeKMSAsset("a", "key-1", "confidential"),
			makeKMSAsset("b", "key-1", "confidential"),
		},
	}}
	enriched := EnrichKeyIsolation(snaps)
	crypto := enriched[0].Assets[0].Properties["cryptography"].(map[string]any)
	iso := crypto["key_isolation"].(map[string]any)
	if exclusive, ok := iso["is_exclusive_to_domain"].(bool); !ok || !exclusive {
		t.Fatal("expected is_exclusive_to_domain=true for same-classification key")
	}
	if mixed, ok := iso["mixed_classification"].(bool); !ok || mixed {
		t.Fatal("expected mixed_classification=false for same-classification key")
	}
	if count, ok := iso["domain_count"].(int); !ok || count != 1 {
		t.Fatalf("expected domain_count=1, got %v", iso["domain_count"])
	}
}

func TestBuildKeyUsageIndex_MinMaxUpdated(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeKMSAsset("a", "key-1", "phi"),
			makeKMSAsset("b", "key-1", "public"),
		},
	}
	idx := buildKeyUsageIndexForSnapshot(snap)
	entry := idx["key-1"]
	if entry == nil {
		t.Fatal("expected entry for key-1")
	}
	if entry.MinLevel != SensitivityPublic {
		t.Fatalf("expected MinLevel=Public(%d), got %d", SensitivityPublic, entry.MinLevel)
	}
	if entry.MaxLevel != SensitivityPHI {
		t.Fatalf("expected MaxLevel=PHI(%d), got %d", SensitivityPHI, entry.MaxLevel)
	}
}

func TestBuildKeyUsageIndex_MinUpdatedWhenSecondIsLower(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeKMSAsset("a", "key-1", "confidential"),
			makeKMSAsset("b", "key-1", "public"),
		},
	}
	idx := buildKeyUsageIndexForSnapshot(snap)
	entry := idx["key-1"]
	if entry.MinLevel != SensitivityPublic {
		t.Fatalf("MinLevel should update to lower value; got %d, want %d", entry.MinLevel, SensitivityPublic)
	}
	if entry.MaxLevel != SensitivityConfidential {
		t.Fatalf("MaxLevel should stay at higher value; got %d, want %d", entry.MaxLevel, SensitivityConfidential)
	}
}

func TestBuildKeyUsageIndex_MaxUpdatedWhenSecondIsHigher(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeKMSAsset("a", "key-1", "public"),
			makeKMSAsset("b", "key-1", "phi"),
		},
	}
	idx := buildKeyUsageIndexForSnapshot(snap)
	entry := idx["key-1"]
	if entry.MinLevel != SensitivityPublic {
		t.Fatalf("MinLevel should remain; got %d, want %d", entry.MinLevel, SensitivityPublic)
	}
	if entry.MaxLevel != SensitivityPHI {
		t.Fatalf("MaxLevel should update to higher value; got %d, want %d", entry.MaxLevel, SensitivityPHI)
	}
}

func TestExtractKMSKeyID_NoCryptographyProperty(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{"foo": "bar"}}
	if got := extractKMSKeyID(a); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestExtractKMSKeyID_CryptographyNotMap(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{"cryptography": "string"}}
	if got := extractKMSKeyID(a); got != "" {
		t.Fatalf("expected empty for non-map cryptography, got %q", got)
	}
}

func TestExtractKMSKeyID_NoKeyIDField(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"cryptography": map[string]any{"algorithm": "AES256"},
	}}
	if got := extractKMSKeyID(a); got != "" {
		t.Fatalf("expected empty for missing kms_key_id, got %q", got)
	}
}

func TestEnrichAssetIsolation_NoKeyID(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{"foo": "bar"}}
	idx := KeyUsageIndex{"some-key": &KeyUsageEntry{}}
	enriched := enrichAssetIsolation(a, idx)
	if _, ok := enriched.Properties["cryptography"]; ok {
		t.Fatal("should not add cryptography when asset has no key")
	}
	enriched.Properties["injected"] = true
	if _, ok := a.Properties["injected"]; ok {
		t.Fatal("enrichAssetIsolation must clone properties even on no-op path")
	}
}

func TestEnrichAssetIsolation_KeyNotInIndex(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"cryptography": map[string]any{"kms_key_id": "orphan-key"},
	}}
	idx := KeyUsageIndex{"other-key": &KeyUsageEntry{}}
	enriched := enrichAssetIsolation(a, idx)
	crypto := enriched.Properties["cryptography"].(map[string]any)
	if _, ok := crypto["key_isolation"]; ok {
		t.Fatal("should not add key_isolation when key is not in index")
	}
}

// --- Identity index edge cases (identity_index.go) ---

func TestIdentityIndex_EmptyIndex(t *testing.T) {
	idx := IdentityIndex{}
	if got := idx.At(time.Now()); got != nil {
		t.Fatalf("empty index should return nil, got %v", got)
	}
}

func TestIdentityIndex_ExactMatchLastEntry(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: base, Identities: []asset.CloudIdentity{{ID: "id-1"}}},
		{CapturedAt: base.Add(time.Hour), Identities: []asset.CloudIdentity{{ID: "id-2"}}},
	})
	ids := idx.At(base.Add(time.Hour))
	if len(ids) != 1 || ids[0].ID != "id-2" {
		t.Fatalf("exact match on last entry should return id-2, got %v", ids)
	}
}

func TestIdentityIndex_FallbackAfterLastEntry(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: base, Identities: []asset.CloudIdentity{{ID: "id-1"}}},
		{CapturedAt: base.Add(time.Hour), Identities: []asset.CloudIdentity{{ID: "id-2"}}},
	})
	ids := idx.At(base.Add(2 * time.Hour))
	if len(ids) != 1 || ids[0].ID != "id-2" {
		t.Fatalf("query after last entry should fallback to last, got %v", ids)
	}
}

func TestBuildIdentityIndex_EmptySnapshots(t *testing.T) {
	idx := BuildIdentityIndex(nil)
	if len(idx.entries) != 0 {
		t.Fatalf("nil snapshots should produce empty index, got %d entries", len(idx.entries))
	}
	idx = BuildIdentityIndex([]asset.Snapshot{})
	if len(idx.entries) != 0 {
		t.Fatalf("empty snapshots should produce empty index, got %d entries", len(idx.entries))
	}
}

func TestBuildIdentityIndex_SortOrder(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: base.Add(2 * time.Hour), Identities: []asset.CloudIdentity{{ID: "late"}}},
		{CapturedAt: base, Identities: []asset.CloudIdentity{{ID: "early"}}},
	})
	if len(idx.entries) != 2 {
		t.Fatal("expected 2 entries")
	}
	if idx.entries[0].capturedAt.After(idx.entries[1].capturedAt) {
		t.Fatal("entries should be sorted chronologically")
	}
}

func TestMergeIdentitiesAt_FirstEntryMerge(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: base, Identities: []asset.CloudIdentity{{ID: "a"}}},
		{CapturedAt: base, Identities: []asset.CloudIdentity{{ID: "b"}}},
		{CapturedAt: base.Add(time.Hour), Identities: []asset.CloudIdentity{{ID: "c"}}},
	})
	ids := idx.At(base)
	if len(ids) != 2 {
		t.Fatalf("expected 2 merged identities at start, got %d", len(ids))
	}
}

// --- evidence_hook.go: isSensitiveField ---

func TestIsSensitiveField_MatchesToken(t *testing.T) {
	if !isSensitiveField("db_password_hash") {
		t.Error("'password' token should be sensitive")
	}
}

func TestIsSensitiveField_NoMatch(t *testing.T) {
	if isSensitiveField("bucket_name") {
		t.Error("'bucket_name' should not be sensitive")
	}
}

func TestIsSensitiveField_Delimiters(t *testing.T) {
	for _, key := range []string{"my-secret-key", "my.secret.key", "my:secret:key", "my_secret_key"} {
		if !isSensitiveField(key) {
			t.Errorf("%q should be sensitive (contains 'secret')", key)
		}
	}
}

func TestIsSensitiveField_CaseInsensitive(t *testing.T) {
	if !isSensitiveField("API_TOKEN") {
		t.Error("uppercase TOKEN should be sensitive")
	}
}

func TestIsSensitiveField_EmptyString(t *testing.T) {
	if isSensitiveField("") {
		t.Error("empty string should not be sensitive")
	}
}

// --- evidence_hook.go: complianceToMap ---

func TestComplianceToMap_Empty(t *testing.T) {
	got := complianceToMap(nil)
	if got != nil {
		t.Fatalf("nil input should return nil, got %v", got)
	}
	got = complianceToMap(policy.ComplianceMapping{})
	if got != nil {
		t.Fatalf("empty input should return nil, got %v", got)
	}
}

func TestComplianceToMap_Populated(t *testing.T) {
	cm := policy.ComplianceMapping{
		"cis": "1.1",
		"nist": "AC-2",
	}
	got := complianceToMap(cm)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got["cis"] != "1.1" || got["nist"] != "AC-2" {
		t.Fatalf("unexpected values: %v", got)
	}
}

// --- evidence_hook.go: lookupProperties ---

func TestLookupProperties_NilSnap(t *testing.T) {
	if got := lookupProperties(nil, "a"); got != nil {
		t.Fatalf("nil snap should return nil, got %v", got)
	}
}

func TestLookupProperties_AssetNotFound(t *testing.T) {
	snap := &asset.Snapshot{
		Assets: []asset.Asset{{ID: "x", Properties: map[string]any{"k": "v"}}},
	}
	if got := lookupProperties(snap, "missing"); got != nil {
		t.Fatalf("missing asset should return nil, got %v", got)
	}
}

func TestLookupProperties_AssetFound(t *testing.T) {
	snap := &asset.Snapshot{
		Assets: []asset.Asset{{ID: "a", Properties: map[string]any{"k": "v"}}},
	}
	got := lookupProperties(snap, "a")
	if got == nil || got["k"] != "v" {
		t.Fatalf("expected properties, got %v", got)
	}
}

// --- finding_builder.go: borrowFinding / ReturnFindings ---

func TestBorrowFinding_ReturnsCleanFinding(t *testing.T) {
	f := borrowFinding()
	if f == nil {
		t.Fatal("borrowFinding returned nil")
	}
	if f.ControlID != "" || f.AssetID != "" {
		t.Fatal("borrowed finding should be zero-valued")
	}
}

func TestReturnFindings_NilSafe(t *testing.T) {
	ReturnFindings(nil)
	ReturnFindings([]*evaluation.Finding{nil, nil})
}

func TestBorrowFinding_PoolRoundTrip(t *testing.T) {
	f := borrowFinding()
	f.ControlID = "CTL.X"
	ReturnFindings([]*evaluation.Finding{f})
	f2 := borrowFinding()
	if f2.ControlID != "" {
		t.Fatal("finding from pool should be zeroed on borrow")
	}
}

// --- finding_builder.go: NewFinding ---

func TestNewFinding_NilControl(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	if got := NewFinding(nil, lc, FindingContext{}); got != nil {
		t.Fatal("nil control should return nil finding")
	}
}

func TestNewFinding_EmptyControlID(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "", Name: "empty"}
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	if got := NewFinding(ctl, lc, FindingContext{}); got != nil {
		t.Fatal("empty ControlID should return nil finding")
	}
}

func TestNewFinding_PopulatesMisconfigs(t *testing.T) {
	ctl := testControl("CTL.T.001", policy.TypeUnsafeState)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	ctx := FindingContext{
		Reason: "test reason",
		Misconfigs: []policy.Misconfiguration{
			{Property: predicate.NewFieldPath("encryption.enabled"), Operator: predicate.OpEq, UnsafeValue: false, ActualValue: true},
		},
	}
	f := NewFinding(ctl, lc, ctx)
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.TemporalRisk != "test reason" {
		t.Fatalf("expected reason 'test reason', got %q", f.Evidence.TemporalRisk)
	}
	if len(f.Evidence.Misconfigurations) != 1 {
		t.Fatalf("expected 1 misconfiguration, got %d", len(f.Evidence.Misconfigurations))
	}
}

// --- coverage.go: NewCoverageValidator ---

func TestNewCoverageValidator_ZeroMinSpan(t *testing.T) {
	_, err := NewCoverageValidator(0, 0)
	if err == nil {
		t.Fatal("zero minSpan should error")
	}
}

func TestNewCoverageValidator_NegativeMinSpan(t *testing.T) {
	_, err := NewCoverageValidator(-time.Hour, 0)
	if err == nil {
		t.Fatal("negative minSpan should error")
	}
}

func TestNewCoverageValidator_MaxGapExceedsMinSpan(t *testing.T) {
	_, err := NewCoverageValidator(time.Hour, 2*time.Hour)
	if err == nil {
		t.Fatal("maxGap > minSpan should error")
	}
}

func TestNewCoverageValidator_EqualSpanAndGap(t *testing.T) {
	v, err := NewCoverageValidator(time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("minSpan == maxGap should be valid, got %v", err)
	}
	if v == nil {
		t.Fatal("validator should not be nil")
	}
}

// --- coverage.go: IsSufficient ---

func TestIsSufficient_NilLifecycleReturnsFalse(t *testing.T) {
	v, _ := NewCoverageValidator(24*time.Hour, 12*time.Hour)
	reason, ok := v.IsSufficient(nil)
	if ok {
		t.Fatal("nil lifecycle should be insufficient")
	}
	if reason == "" {
		t.Fatal("expected a reason string")
	}
}

func TestIsSufficient_ShortWindow(t *testing.T) {
	v, _ := NewCoverageValidator(48*time.Hour, 24*time.Hour)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = lc.RecordCheck(base, false)
	_ = lc.RecordCheck(base.Add(time.Hour), false)
	_, ok := v.IsSufficient(lc)
	if ok {
		t.Fatal("1h span should be insufficient for 48h validator")
	}
}

// --- exposure.go: EvaluatePrefixExposureForRow ---

func TestEvaluatePrefixExposureForRow_NoProtectedPrefixes(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	ctl := testControl("CTL.P.001", policy.TypePrefixExposure)
	row, findings := EvaluatePrefixExposureForRow(lc, ctl)
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("no protected prefixes should produce violation, got %s", row.Verdict)
	}
	if len(findings) == 0 {
		t.Fatal("expected config-issue finding for missing protected prefixes")
	}
}

func TestNewPrefixExposureRow_NilLifecycleOnly(t *testing.T) {
	ctl := testControl("CTL.P.001", policy.TypePrefixExposure)
	row := newPrefixExposureRow(nil, ctl)
	if row.ControlID != "" {
		t.Fatal("nil lifecycle should produce empty row")
	}
}

// --- finding_gen.go: CreateDurationFinding ---

func TestCreateDurationFinding_NilLifecycleErrors(t *testing.T) {
	ctl := testControl("CTL.D.001", policy.TypeUnsafeDuration)
	f, err := CreateDurationFinding(DurationFindingInput{
		Control: ctl,
	})
	if f != nil {
		t.Fatal("nil lifecycle should return nil finding")
	}
	if err == nil {
		t.Fatal("nil lifecycle should return error")
	}
}

func TestCreateDurationFinding_NilControlErrors(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	f, err := CreateDurationFinding(DurationFindingInput{
		ExposureLifecycle: lc,
	})
	if f != nil {
		t.Fatal("nil control should return nil finding")
	}
	if err == nil {
		t.Fatal("nil control should return error")
	}
}

func TestCreateDurationFinding_SetsThresholdHours(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	_ = lc.RecordCheck(base, true)
	_ = lc.RecordCheck(base.Add(48*time.Hour), true)

	ctl := testControl("CTL.D.001", policy.TypeUnsafeDuration)
	f, _ := CreateDurationFinding(DurationFindingInput{
		ExposureLifecycle: lc,
		Control:           ctl,
		Threshold:         168 * time.Hour,
		EvalTime:          base.Add(48 * time.Hour),
	})
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.ThresholdHours != 168 {
		t.Fatalf("expected ThresholdHours=168, got %f", f.Evidence.ThresholdHours)
	}
}

// --- finding_gen.go: DeriveRootCauses ---

func TestDeriveRootCauses_NilInput(t *testing.T) {
	if got := DeriveRootCauses(nil); len(got) != 0 {
		t.Fatalf("nil input should return empty, got %v", got)
	}
}

func TestDeriveRootCauses_IdentityAndResource(t *testing.T) {
	ms := []policy.Misconfiguration{
		{Category: policy.CategoryIdentity},
		{Category: policy.CategoryResource},
	}
	causes := DeriveRootCauses(ms)
	if len(causes) != 2 {
		t.Fatalf("expected 2 causes, got %d", len(causes))
	}
	if causes[0] != evaluation.RootCauseIdentity {
		t.Errorf("first cause should be identity, got %v", causes[0])
	}
	if causes[1] != evaluation.RootCauseResource {
		t.Errorf("second cause should be resource, got %v", causes[1])
	}
}

func TestDeriveRootCauses_UncategorizedFallsToGeneral(t *testing.T) {
	ms := []policy.Misconfiguration{{Category: policy.CategoryUnknown}}
	causes := DeriveRootCauses(ms)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseGeneral {
		t.Fatalf("expected [general], got %v", causes)
	}
}

func TestDeriveRootCauses_EmptySlice(t *testing.T) {
	if got := DeriveRootCauses([]policy.Misconfiguration{}); len(got) != 0 {
		t.Fatalf("empty slice should return empty, got %v", got)
	}
}

// --- finding_gen.go: ExtractSourceEvidence ---

func TestExtractSourceEvidence_NoCauses(t *testing.T) {
	a := asset.Asset{ID: "a"}
	if got := ExtractSourceEvidence(a, nil); got != nil {
		t.Fatalf("no causes should return nil, got %v", got)
	}
}

func TestExtractSourceEvidence_IdentityCause(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"source_evidence": map[string]any{
			"policy_public_statements": []any{"AllowReadOnly", "AllowWrite"},
		},
	}}
	ev := ExtractSourceEvidence(a, []evaluation.RootCause{evaluation.RootCauseIdentity})
	if ev == nil {
		t.Fatal("expected non-nil evidence for identity cause with statements")
	}
	if !ev.HasIdentityStatements() {
		t.Fatal("expected identity statements")
	}
}

func TestExtractSourceEvidence_ResourceCause(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"source_evidence": map[string]any{
			"acl_public_grantees": []any{"http://acs.amazonaws.com/groups/global/AllUsers"},
		},
	}}
	ev := ExtractSourceEvidence(a, []evaluation.RootCause{evaluation.RootCauseResource})
	if ev == nil {
		t.Fatal("expected non-nil evidence for resource cause with grantees")
	}
	if !ev.HasResourceGrantees() {
		t.Fatal("expected resource grantees")
	}
}

func TestExtractSourceEvidence_NilWhenNoData(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{}}
	ev := ExtractSourceEvidence(a, []evaluation.RootCause{evaluation.RootCauseIdentity})
	if ev != nil {
		t.Fatal("expected nil when no statements/grantees found")
	}
}

// --- finding_gen.go: toSorted ---

func TestToSorted_NilInput(t *testing.T) {
	if got := toSorted[kernel.StatementID](nil); got != nil {
		t.Fatalf("nil should return nil, got %v", got)
	}
}

func TestToSorted_EmptyInput(t *testing.T) {
	if got := toSorted[kernel.StatementID]([]string{}); got != nil {
		t.Fatalf("empty should return nil, got %v", got)
	}
}

// --- recurrence.go: CreateRecurrenceFinding ---

func TestCreateRecurrenceFinding_PopulatesEvidence(t *testing.T) {
	ctl := testControl("CTL.R.001", policy.TypeUnsafeRecurrence)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	stats := RecurrenceStats{Count: 5, First: base, Last: base.Add(72 * time.Hour)}
	f := CreateRecurrenceFinding(lc, ctl, stats)
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.ExposureWindowCount != 5 {
		t.Fatalf("expected 5 windows, got %d", f.Evidence.ExposureWindowCount)
	}
	if f.Evidence.FirstUnsafeAt != base {
		t.Fatalf("first unsafe should match first, got %v", f.Evidence.FirstUnsafeAt)
	}
	if f.Evidence.LastSeenUnsafeAt != base.Add(72*time.Hour) {
		t.Fatalf("last unsafe should match last, got %v", f.Evidence.LastSeenUnsafeAt)
	}
}

// --- collector.go: RecordCheck empty ControlID ---

func TestRecordCheck_EmptyControlIDDropped(t *testing.T) {
	c := NewCollector(10)
	c.RecordCheck(evaluation.ResourceCheck{ControlID: "", AssetID: "a"})
	snap := c.Snapshot()
	if len(snap.Checks) != 0 {
		t.Fatal("empty ControlID check should be dropped")
	}
}

func TestRecordCheck_ValidControlAppended(t *testing.T) {
	c := NewCollector(10)
	c.RecordCheck(evaluation.ResourceCheck{ControlID: "CTL.A", AssetID: "a"})
	snap := c.Snapshot()
	if len(snap.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(snap.Checks))
	}
}

// --- collector.go: RecordFindings dedup ---

func TestRecordFindings_DedupByFindingID(t *testing.T) {
	c := NewCollector(10)
	f1 := &evaluation.Finding{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"}
	f2 := &evaluation.Finding{FindingID: "f1", ControlID: "CTL.A", AssetID: "a"}
	c.RecordFindings([]*evaluation.Finding{f1})
	c.RecordFindings([]*evaluation.Finding{f2})
	snap := c.Snapshot()
	if len(snap.Findings) != 1 {
		t.Fatalf("duplicate FindingID should be deduped; got %d findings", len(snap.Findings))
	}
}

func TestRecordFindings_NilInSlice(t *testing.T) {
	c := NewCollector(10)
	c.RecordFindings([]*evaluation.Finding{nil})
	snap := c.Snapshot()
	if len(snap.Findings) != 0 {
		t.Fatal("nil findings should be skipped")
	}
}

func TestRecordFindings_UnattributedDropped(t *testing.T) {
	c := NewCollector(10)
	c.RecordFindings([]*evaluation.Finding{{FindingID: "f1", ControlID: "", AssetID: ""}})
	snap := c.Snapshot()
	if len(snap.Findings) != 0 {
		t.Fatal("unattributed finding should be skipped")
	}
}

func TestRecordFindings_FallbackIDWhenEmpty(t *testing.T) {
	c := NewCollector(10)
	c.RecordFindings([]*evaluation.Finding{{FindingID: "", ControlID: "CTL.A", AssetID: "a"}})
	snap := c.Snapshot()
	if len(snap.Findings) != 1 {
		t.Fatal("finding with empty FindingID should use fallback and be recorded")
	}
}

// --- collector.go: Snapshot deep-clone ---

func TestSnapshot_DeepClone(t *testing.T) {
	c := NewCollector(10)
	c.RecordFindings([]*evaluation.Finding{
		{
			FindingID: "f1", ControlID: "CTL.A", AssetID: "a",
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{{Property: predicate.NewFieldPath("x")}},
				RootCauses:        []evaluation.RootCause{evaluation.RootCauseGeneral},
			},
		},
	})
	snap := c.Snapshot()
	if len(snap.Findings) != 1 {
		t.Fatal("expected 1 finding")
	}
	snap.Findings[0].Evidence.RootCauses = append(snap.Findings[0].Evidence.RootCauses, evaluation.RootCauseIdentity)
	snap2 := c.Snapshot()
	if len(snap2.Findings[0].Evidence.RootCauses) != 1 {
		t.Fatal("snapshot mutation should not affect collector state")
	}
}

// --- collector.go: RecordSkippedControl ---

func TestRecordSkippedControl(t *testing.T) {
	c := NewCollector(10)
	c.RecordSkippedControl("CTL.SKIP", "skip", "not evaluatable")
	snap := c.Snapshot()
	if len(snap.SkippedControls) != 1 {
		t.Fatalf("expected 1 skipped control, got %d", len(snap.SkippedControls))
	}
	if snap.SkippedControls[0].Reason != "not evaluatable" {
		t.Fatalf("unexpected reason: %q", snap.SkippedControls[0].Reason)
	}
}

// --- collector.go: stripeIndex determinism ---

func TestStripeIndex_DeterministicHash(t *testing.T) {
	a := stripeIndex("bucket-1")
	b := stripeIndex("bucket-1")
	if a != b {
		t.Fatal("stripeIndex should be deterministic")
	}
}

func TestStripeIndex_InRange(t *testing.T) {
	for _, id := range []asset.ID{"a", "b", "bucket-prod-123", ""} {
		idx := stripeIndex(id)
		if idx < 0 || idx >= stripeCount {
			t.Fatalf("stripeIndex(%q) = %d, out of range [0, %d)", id, idx, stripeCount)
		}
	}
}

// --- collector.go: assetRegistry ---

func TestAssetRegistry_RegisterOnce(t *testing.T) {
	r := make(assetRegistry)
	if !r.register("a") {
		t.Error("first register should return true")
	}
	if r.register("a") {
		t.Error("second register should return false")
	}
}

// --- lifecycles.go: BuildLifecyclesPerControl ---

func TestBuildLifecyclesPerControl_NilCtxUsesBackground(t *testing.T) {
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := newLifecycleBuilder(base).
		at(0, "a").
		at(48*time.Hour, "a").
		build()
	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	lcs, err := BuildLifecyclesPerControl(nil, []policy.ControlDefinition{ctl}, snaps, eval)
	if err != nil {
		t.Fatalf("nil context should use background, got error: %v", err)
	}
	if len(lcs) != 1 {
		t.Fatalf("expected 1 control map, got %d", len(lcs))
	}
}

func TestBuildLifecyclesPerControl_CancelledCtxErrors(t *testing.T) {
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := newLifecycleBuilder(base).
		at(0, "a").
		at(48*time.Hour, "a").
		build()
	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := BuildLifecyclesPerControl(ctx, []policy.ControlDefinition{ctl}, snaps, eval)
	if err == nil {
		t.Fatal("cancelled context should return error")
	}
}

// --- lifecycles.go: checkUnsafe ---

func TestCheckUnsafe_NilEvaluatorReturnsError(t *testing.T) {
	ctl := testControl("CTL.T.001", policy.TypeUnsafeState)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	snap := asset.Snapshot{}
	_, err := checkUnsafe(ctl, a, snap, nil)
	if err == nil {
		t.Fatal("nil evaluator should error")
	}
}

func TestCheckUnsafe_ReturnsResult(t *testing.T) {
	ctl := testControl("CTL.T.001", policy.TypeUnsafeState)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	snap := asset.Snapshot{}
	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	}
	unsafe, err := checkUnsafe(ctl, a, snap, eval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !unsafe {
		t.Fatal("expected unsafe=true")
	}
}

// --- lifecycles.go: controlVendorIndex ---

func TestControlVendorIndex_CacheHit(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:        "CTL.T.001",
		ScopeTags: []kernel.ScopeTag{"aws"},
	}
	idx := buildControlVendorIndex([]policy.ControlDefinition{ctl})
	all := []policy.ControlDefinition{ctl}
	r1 := idx.controlsFor("aws", all)
	r2 := idx.controlsFor("aws", all)
	if len(r1) != 1 || len(r2) != 1 {
		t.Fatalf("expected 1 control both times, got %d and %d", len(r1), len(r2))
	}
}

func TestControlVendorIndex_ReturnedSliceIndependent(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:        "CTL.T.001",
		ScopeTags: []kernel.ScopeTag{"aws"},
	}
	idx := buildControlVendorIndex([]policy.ControlDefinition{ctl})
	all := []policy.ControlDefinition{ctl}
	r1 := idx.controlsFor("aws", all)
	r1[0].ID = "MUTATED"
	r2 := idx.controlsFor("aws", all)
	if r2[0].ID != "CTL.T.001" {
		t.Fatal("mutating returned slice should not corrupt cache")
	}
}

// --- lifecycles.go: ErrNilCELEvaluator ---

func TestErrNilCELEvaluator_IsDetectable(t *testing.T) {
	ctl := testControl("CTL.T.001", policy.TypeUnsafeState)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	_, err := checkUnsafe(ctl, a, asset.Snapshot{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !isNilEvalErr(err) {
		t.Fatal("error should wrap ErrNilCELEvaluator")
	}
}

func isNilEvalErr(err error) bool {
	return err != nil && err.Error() != "" && err.Error() != "nil"
}

// --- RecordExemptedAsset ---

func TestRecordExemptedAsset(t *testing.T) {
	c := NewCollector(10)
	c.RecordExemptedAsset("a", "a-*", "test")
	snap := c.Snapshot()
	if len(snap.ExemptedAssets) != 1 {
		t.Fatalf("expected 1 exempted asset, got %d", len(snap.ExemptedAssets))
	}
	if snap.ExemptedAssets[0].Reason != "test" {
		t.Fatalf("unexpected reason: %q", snap.ExemptedAssets[0].Reason)
	}
}

// --- newPrefixExposureRow nil guards ---

func TestNewPrefixExposureRow_NilInputs(t *testing.T) {
	row := newPrefixExposureRow(nil, nil)
	if row.ControlID != "" {
		t.Fatal("nil inputs should produce empty row")
	}
}

func TestNewPrefixExposureRow_ValidInputs(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	ctl := testControl("CTL.P.001", policy.TypePrefixExposure)
	row := newPrefixExposureRow(lc, ctl)
	if row.ControlID != "CTL.P.001" {
		t.Fatalf("expected CTL.P.001, got %s", row.ControlID)
	}
	if row.Verdict != evaluation.VerdictPass {
		t.Fatalf("default verdict should be pass, got %s", row.Verdict)
	}
}

// --- buildEvidencePackage nil controls ---

func TestBuildEvidencePackage_EmptyInputs(t *testing.T) {
	pkg := buildEvidencePackage(nil, nil, nil, nil, time.Now())
	if pkg == nil {
		t.Fatal("should return non-nil package even with empty inputs")
	}
}

// --- GovernanceConfig ---

func TestGovernanceConfig_ConfidenceDerive(t *testing.T) {
	g := GovernanceConfig{
		slaThreshold: 168 * time.Hour,
		confidence:   evaluation.DefaultConfidenceCalculator(),
	}
	got := g.confidence.Derive(time.Hour, 168*time.Hour)
	if got != evaluation.ConfidenceHigh {
		t.Fatalf("expected high confidence, got %v", got)
	}
}

// --- Assessor.Assess with evidence generation + safe asset ---

func TestAssess_EvidenceGenerationSafeAsset(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()
	ctl.Compliance = policy.ComplianceMapping{"cis": "1.1"}

	a := newTestAssessor().
		withClock(base.Add(48 * time.Hour)).
		withControls(ctl).
		alwaysSafe().
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
		t.Fatal("evidence should be generated even for safe assets with compliance mappings")
	}
}

// --- BuildLifecyclesPerControl with unsafe eval ---

func TestBuildLifecyclesPerControl_UnsafeEval(t *testing.T) {
	ctl := newTestControl("CTL.T.001").typed(policy.TypeUnsafeState).build()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := newLifecycleBuilder(base).
		at(0, "a").
		at(48*time.Hour, "a").
		build()
	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	}
	lcs, err := BuildLifecyclesPerControl(context.Background(), []policy.ControlDefinition{ctl}, snaps, eval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctlLCs := lcs["CTL.T.001"]
	if len(ctlLCs) != 1 {
		t.Fatalf("expected 1 lifecycle, got %d", len(ctlLCs))
	}
	lc := ctlLCs["a"]
	if lc == nil {
		t.Fatal("lifecycle for asset 'a' should exist")
	}
	if !lc.HasActiveWindow() {
		t.Fatal("asset evaluated unsafe twice should have active window")
	}
}

// --- Collector NewCollector pre-allocation ---

func TestNewCollector_AllStripesInitialized(t *testing.T) {
	c := NewCollector(0)
	for i := range c.stripes {
		if c.stripes[i] == nil {
			t.Fatalf("stripe %d should not be nil", i)
		}
	}
}

// --- testAssessor with FixedClock (for port coverage) ---

func TestFixedClock_UsedByAssessor(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	a := testAssessor(168*time.Hour, now)
	if a.clock == nil {
		t.Fatal("testAssessor should set clock via ports.FixedClock")
	}
	clk, ok := a.clock.(ports.FixedClock)
	if !ok {
		t.Fatal("expected ports.FixedClock type")
	}
	if !clk.Now().Equal(now) {
		t.Fatalf("clock should report %v, got %v", now, clk.Now())
	}
}
