package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// BuildTimelinesPerControl
// ---------------------------------------------------------------------------

func TestBuildTimelinesPerControl_Basic(t *testing.T) {
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

	timelines, err := BuildTimelinesPerControl(controls, snapshots, celEval)
	if err != nil {
		t.Fatalf("BuildTimelinesPerControl: %v", err)
	}

	tlMap, ok := timelines["CTL.A.001"]
	if !ok {
		t.Fatal("missing control timelines")
	}
	tl, ok := tlMap["bucket-1"]
	if !ok {
		t.Fatal("missing asset timeline")
	}
	if tl.CurrentlyUnsafe() {
		t.Fatal("asset should be safe")
	}
}

func TestBuildTimelinesPerControl_UnsafePredicate(t *testing.T) {
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

	timelines, err := BuildTimelinesPerControl(controls, snapshots, celEval)
	if err != nil {
		t.Fatal(err)
	}
	tl := timelines["CTL.A.001"]["bucket-1"]
	if !tl.CurrentlyUnsafe() {
		t.Fatal("asset should be unsafe")
	}
}

func TestBuildTimelinesPerControl_NilEvaluator(t *testing.T) {
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

	// Nil evaluator should return safe (false)
	timelines, err := BuildTimelinesPerControl(controls, snapshots, nil)
	if err != nil {
		t.Fatal(err)
	}
	tl := timelines["CTL.A.001"]["bucket-1"]
	if tl.CurrentlyUnsafe() {
		t.Fatal("nil evaluator should default to safe")
	}
}

// ---------------------------------------------------------------------------
// checkUnsafe
// ---------------------------------------------------------------------------

func TestCheckUnsafe_NilEvaluator(t *testing.T) {
	ctl := policy.ControlDefinition{ID: "CTL.A.001"}
	a := asset.Asset{ID: "bucket-1"}
	snap := asset.Snapshot{}

	result := checkUnsafe(ctl, a, snap, nil)
	if result {
		t.Fatal("nil evaluator should return false")
	}
}

func TestCheckUnsafe_EvaluatorError(t *testing.T) {
	ctl := policy.ControlDefinition{ID: "CTL.A.001"}
	a := asset.Asset{ID: "bucket-1"}
	snap := asset.Snapshot{}

	eval := func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, fmt.Errorf("some error")
	}

	result := checkUnsafe(ctl, a, snap, eval)
	if result {
		t.Fatal("error should return false")
	}
}

// ---------------------------------------------------------------------------
// strategyFor
// ---------------------------------------------------------------------------

func TestStrategyFor(t *testing.T) {
	r := &Runner{}

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
		s := r.strategyFor(ctl)
		if s == nil {
			t.Fatalf("strategyFor(%v) returned nil", tt.ctlType)
		}
	}
}

// ---------------------------------------------------------------------------
// Runner.computePackHash
// ---------------------------------------------------------------------------

type testDigester struct{}

func (d *testDigester) Digest(items []string, sep byte) kernel.Digest {
	return kernel.Digest("sha256:testhash")
}

func TestRunnerComputePackHash_Empty(t *testing.T) {
	r := &Runner{Hasher: &testDigester{}}
	if hash := r.computePackHash(); hash != "" {
		t.Fatalf("empty controls should return empty hash, got %v", hash)
	}
}

func TestRunnerComputePackHash_NilHasher(t *testing.T) {
	r := &Runner{
		Controls: []policy.ControlDefinition{{ID: "CTL.A.001"}},
	}
	if hash := r.computePackHash(); hash != "" {
		t.Fatalf("nil hasher should return empty hash, got %v", hash)
	}
}

func TestRunnerComputePackHash_WithControls(t *testing.T) {
	r := &Runner{
		Controls: []policy.ControlDefinition{
			{ID: "CTL.B.001"},
			{ID: "CTL.A.001"},
		},
		Hasher: &testDigester{},
	}
	hash := r.computePackHash()
	if hash != "sha256:testhash" {
		t.Fatalf("expected hash, got %v", hash)
	}
}

// ---------------------------------------------------------------------------
// Runner.deterministicNow
// ---------------------------------------------------------------------------

type stubClock struct{ t time.Time }

func (c stubClock) Now() time.Time { return c.t }

func TestDeterministicNow_FromSnapshots(t *testing.T) {
	base := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	r := &Runner{Clock: stubClock{t: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}}
	sorted := []asset.Snapshot{
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
	}
	now := r.deterministicNow(sorted)
	if !now.Equal(base.Add(time.Hour)) {
		t.Fatalf("expected last snapshot time, got %v", now)
	}
}

func TestDeterministicNow_Fallback(t *testing.T) {
	fallback := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	r := &Runner{Clock: stubClock{t: fallback}}
	now := r.deterministicNow(nil)
	if !now.Equal(fallback) {
		t.Fatalf("expected clock fallback, got %v", now)
	}
}

// ---------------------------------------------------------------------------
// Runner.Evaluate — basic smoke test
// ---------------------------------------------------------------------------

func TestRunnerEvaluate_NilClock(t *testing.T) {
	r := &Runner{}
	_, err := r.Evaluate(nil)
	if err == nil {
		t.Fatal("expected error for nil clock")
	}
}

func TestRunnerEvaluate_EmptySnapshots(t *testing.T) {
	r := &Runner{
		Clock:      stubClock{t: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)},
		Exemptions: policy.NewExemptionConfig("", nil),
		Exceptions: policy.NewExceptionConfig(nil),
	}
	result, err := r.Evaluate(nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.SafetyStatus != evaluation.StatusSafe {
		t.Fatalf("empty should be safe, got %v", result.SafetyStatus)
	}
}

func TestRunnerEvaluate_BasicViolation(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &Runner{
		Controls: []policy.ControlDefinition{
			{
				ID:       "CTL.A.001",
				Name:     "Test",
				Severity: policy.SeverityHigh,
				Type:     policy.TypeUnsafeState,
			},
		},
		MaxUnsafeDuration: 1 * time.Hour,
		Clock:             stubClock{t: base.Add(48 * time.Hour)},
		Exemptions:        policy.NewExemptionConfig("", nil),
		Exceptions:        policy.NewExceptionConfig(nil),
		CELEvaluator: func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
			return true, nil
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

	result, err := r.Evaluate(snapshots)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.SafetyStatus != evaluation.StatusUnsafe {
		t.Fatalf("expected unsafe, got %v", result.SafetyStatus)
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
	tl, _ := asset.NewTimeline(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Single observation
	_ = tl.RecordObservation(base, false)

	cv := CoverageValidator{MinRequiredSpan: 24 * time.Hour}
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
	tl, _ := asset.NewTimeline(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	_ = tl.RecordObservation(base, false)
	_ = tl.RecordObservation(base.Add(48*time.Hour), false)

	cv := CoverageValidator{MinRequiredSpan: 24 * time.Hour}
	_, ok := cv.IsSufficient(tl)
	if !ok {
		t.Fatal("48h span should be sufficient for 24h requirement")
	}
}
