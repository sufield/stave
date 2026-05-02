package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// BuildLifecyclesPerControl
// ---------------------------------------------------------------------------

func TestBuildLifecyclesPerControl_Basic(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Type: policy.TypeUnsafeState},
	}
	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets:     []asset.Asset{{ID: "bucket-1", Type: "s3_bucket"}},
		},
		{
			CapturedAt: base.Add(time.Hour),
			Assets:     []asset.Asset{{ID: "bucket-1", Type: "s3_bucket"}},
		},
	}

	// Use a simple predicate evaluator that always returns false (safe)
	celEval := func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}

	lifecycles, err := BuildLifecyclesPerControl(controls, snapshots, celEval)
	if err != nil {
		t.Fatalf("BuildLifecyclesPerControl: %v", err)
	}

	tlMap, ok := lifecycles["CTL.A.001"]
	if !ok {
		t.Fatal("missing control lifecycles")
	}
	tl, ok := tlMap["bucket-1"]
	if !ok {
		t.Fatal("missing asset lifecycle")
	}
	if tl.IsExposed() {
		t.Fatal("asset should be safe")
	}
}

func TestBuildLifecyclesPerControl_UnsafePredicate(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Type: policy.TypeUnsafeState},
	}
	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets:     []asset.Asset{{ID: "bucket-1", Type: "s3_bucket"}},
		},
	}

	// Evaluator returns true (unsafe)
	celEval := func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	}

	lifecycles, err := BuildLifecyclesPerControl(controls, snapshots, celEval)
	if err != nil {
		t.Fatal(err)
	}
	tl := lifecycles["CTL.A.001"]["bucket-1"]
	if !tl.IsExposed() {
		t.Fatal("asset should be unsafe")
	}
}

func TestBuildLifecyclesPerControl_NilEvaluator(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Type: policy.TypeUnsafeState},
	}
	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets:     []asset.Asset{{ID: "bucket-1", Type: "s3_bucket"}},
		},
	}

	// Nil evaluator → inconclusive checks are skipped (fail-closed).
	// Lifecycle exists but has no observations, so IsExposed is false.
	lifecycles, err := BuildLifecyclesPerControl(controls, snapshots, nil)
	if err != nil {
		t.Fatal(err)
	}
	tl := lifecycles["CTL.A.001"]["bucket-1"]
	if tl.IsExposed() {
		t.Fatal("nil evaluator should skip recording (inconclusive)")
	}
}

// ---------------------------------------------------------------------------
// checkUnsafe
// ---------------------------------------------------------------------------

func TestCheckUnsafe_NilEvaluator(t *testing.T) {
	ctl := policy.ControlDefinition{ID: "CTL.A.001"}
	a := asset.Asset{ID: "bucket-1"}
	snap := asset.Snapshot{}

	result, err := checkUnsafe(ctl, a, snap, nil)
	if err == nil {
		t.Fatal("nil evaluator should return error")
	}
	if result {
		t.Fatal("nil evaluator result should be false")
	}
}

func TestCheckUnsafe_EvaluatorError(t *testing.T) {
	ctl := policy.ControlDefinition{ID: "CTL.A.001"}
	a := asset.Asset{ID: "bucket-1"}
	snap := asset.Snapshot{}

	eval := func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, errors.New("some error")
	}

	result, err := checkUnsafe(ctl, a, snap, eval)
	if err == nil {
		t.Fatal("evaluator error should propagate")
	}
	if result {
		t.Fatal("error result should be false")
	}
}

// ---------------------------------------------------------------------------
// strategyFor
// ---------------------------------------------------------------------------

func TestStrategyFor(t *testing.T) {
	a := &Assessor{}

	tests := []struct {
		ctlType policy.ControlType
		want    string
	}{
		{policy.TypeUnsafeState, "*engine.unsafeStateStrategy"},
		{policy.TypeUnsafeDuration, "*engine.unsafeDurationStrategy"},
		{policy.TypeUnsafeRecurrence, "*engine.unsafeRecurrenceStrategy"},
		{policy.TypePrefixExposure, "*engine.prefixExposureStrategy"},
		{policy.TypeAuthorizationBoundary, "*engine.unsupportedStrategy"},
		{policy.TypeAudienceBoundary, "*engine.unsupportedStrategy"},
	}

	for _, tt := range tests {
		ctl := &policy.ControlDefinition{Type: tt.ctlType}
		s := a.strategyFor(ctl)
		if s == nil {
			t.Fatalf("strategyFor(%v) returned nil", tt.ctlType)
		}
	}
}

// ---------------------------------------------------------------------------
// Assessor.FingerprintPolicy
// ---------------------------------------------------------------------------

type testDigester struct{}

func (d *testDigester) Digest(_ []string, _ byte) kernel.Digest {
	return kernel.Digest("sha256:testhash")
}

func TestAssessorFingerprintPolicy_Empty(t *testing.T) {
	a := &Assessor{hasher: &testDigester{}}
	if hash := a.FingerprintPolicy(); hash != "" {
		t.Fatalf("empty controls should return empty hash, got %v", hash)
	}
}

func TestAssessorFingerprintPolicy_NilHasher(t *testing.T) {
	a := &Assessor{
		controls: []policy.ControlDefinition{{ID: "CTL.A.001"}},
	}
	if hash := a.FingerprintPolicy(); hash != "" {
		t.Fatalf("nil hasher should return empty hash, got %v", hash)
	}
}

func TestAssessorFingerprintPolicy_WithControls(t *testing.T) {
	a := &Assessor{
		controls: []policy.ControlDefinition{
			{ID: "CTL.B.001"},
			{ID: "CTL.A.001"},
		},
		hasher: &testDigester{},
	}
	hash := a.FingerprintPolicy()
	if hash != "sha256:testhash" {
		t.Fatalf("expected hash, got %v", hash)
	}
}

// ---------------------------------------------------------------------------
// Assessor.referenceTime
// ---------------------------------------------------------------------------

type stubClock struct{ t time.Time }

func (c stubClock) Now() time.Time { return c.t }

func TestReferenceTime_FromSnapshots(t *testing.T) {
	base := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	a := &Assessor{clock: stubClock{t: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}}
	sorted := []asset.Snapshot{
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
	}
	now, err := a.referenceTime(sorted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !now.Equal(base.Add(time.Hour)) {
		t.Fatalf("expected last snapshot time, got %v", now)
	}
}

func TestReferenceTime_Fallback(t *testing.T) {
	fallback := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	a := &Assessor{clock: stubClock{t: fallback}}
	now, err := a.referenceTime(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !now.Equal(fallback) {
		t.Fatalf("expected clock fallback, got %v", now)
	}
}

// TestReferenceTime_NilClockReturnsError pins the new contract: a
// nil Clock surfaces as ErrClockMissing instead of panicking.
func TestReferenceTime_NilClockReturnsError(t *testing.T) {
	a := &Assessor{}
	_, err := a.referenceTime(nil)
	if err == nil {
		t.Fatal("expected ErrClockMissing, got nil")
	}
	if !errors.Is(err, ErrClockMissing) {
		t.Errorf("expected ErrClockMissing, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Assessor.Assess — basic smoke test
// ---------------------------------------------------------------------------

func TestAssessorAssess_NilClock(t *testing.T) {
	a := &Assessor{}
	_, err := a.Assess(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil clock")
	}
}

func TestAssessorAssess_EmptySnapshots(t *testing.T) {
	a := &Assessor{
		clock:      stubClock{t: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)},
		exemptions: policy.NewExemptionConfig("", nil),
		exceptions: policy.NewExceptionConfig(nil),
		predicateEval: func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return false, nil
		},
		predicateParser: func(_ any) (*policy.UnsafePredicate, error) {
			return &policy.UnsafePredicate{}, nil
		},
	}
	result, err := a.Assess(context.Background(), nil)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if result.SecurityState != evaluation.StateCompliant {
		t.Fatalf("empty should be safe, got %v", result.SecurityState)
	}
}

func TestAssessorAssess_BasicViolation(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &Assessor{
		controls: []policy.ControlDefinition{
			{
				ID:       "CTL.A.001",
				Name:     "Test",
				Severity: policy.SeverityHigh,
				Type:     policy.TypeUnsafeState,
			},
		},
		slaThreshold: 1 * time.Hour,
		clock:        stubClock{t: base.Add(48 * time.Hour)},
		exemptions:   policy.NewExemptionConfig("", nil),
		exceptions:   policy.NewExceptionConfig(nil),
		predicateEval: func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return true, nil
		},
		predicateParser: func(_ any) (*policy.UnsafePredicate, error) {
			return &policy.UnsafePredicate{}, nil
		},
	}

	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets:     []asset.Asset{{ID: "bucket-1", Type: "s3_bucket"}},
		},
		{
			CapturedAt: base.Add(48 * time.Hour),
			Assets:     []asset.Asset{{ID: "bucket-1", Type: "s3_bucket"}},
		},
	}

	result, err := a.Assess(context.Background(), snapshots)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if result.SecurityState != evaluation.StateNonCompliant {
		t.Fatalf("expected unsafe, got %v", result.SecurityState)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}
}

// ---------------------------------------------------------------------------
// CoverageValidator
// ---------------------------------------------------------------------------

func TestCoverageValidator(t *testing.T) {
	a := asset.Asset{ID: "bucket-1"}
	tl, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Single observation
	_ = tl.RecordCheck(base, false)

	cv := CoverageValidator{minRequiredSpan: 24 * time.Hour}
	reason, ok := cv.IsSufficient(tl)
	if ok {
		t.Fatal("single observation should be insufficient")
	}
	if reason == "" {
		t.Fatal("expected a reason")
	}
}

func TestCoverageValidator_Sufficient(t *testing.T) {
	a := asset.Asset{ID: "bucket-1"}
	tl, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	_ = tl.RecordCheck(base, false)
	_ = tl.RecordCheck(base.Add(48*time.Hour), false)

	cv := CoverageValidator{minRequiredSpan: 24 * time.Hour}
	_, ok := cv.IsSufficient(tl)
	if !ok {
		t.Fatal("48h span should be sufficient for 24h requirement")
	}
}
