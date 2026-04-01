package engine

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func buildTimeline(t *testing.T, observations []struct {
	at     time.Time
	unsafe bool
}) *asset.Timeline {
	t.Helper()
	a := asset.Asset{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}
	tl, err := asset.NewTimeline(a)
	if err != nil {
		t.Fatalf("NewTimeline: %v", err)
	}
	for _, obs := range observations {
		if err := tl.RecordObservation(obs.at, obs.unsafe); err != nil {
			t.Fatalf("RecordObservation(%v, %v): %v", obs.at, obs.unsafe, err)
		}
	}
	return tl
}

func testRunner(maxUnsafe time.Duration, now time.Time) *Runner {
	return &Runner{
		MaxUnsafeDuration: maxUnsafe,
		Clock:             ports.FixedClock(now),
	}
}

func testControl(id string, ctlType policy.ControlType) *policy.ControlDefinition {
	ctl := &policy.ControlDefinition{
		ID:   kernel.ControlID(id),
		Name: id,
		Type: ctlType,
	}
	return ctl
}

// ---------------------------------------------------------------------------
// unsafeStateStrategy
// ---------------------------------------------------------------------------

func TestUnsafeStateStrategy_SafeAsset(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(2 * time.Hour)

	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
		{base.Add(time.Hour), false},
	})

	s := &unsafeStateStrategy{
		runner: testRunner(4*time.Hour, now),
		ctl:    testControl("CTL.STATE.001", policy.TypeUnsafeState),
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionPass {
		t.Fatalf("expected Pass, got %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestUnsafeStateStrategy_UnsafeExceedsThreshold(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(6 * time.Hour)

	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(time.Hour), true},
	})

	s := &unsafeStateStrategy{
		runner: testRunner(4*time.Hour, now),
		ctl:    testControl("CTL.STATE.001", policy.TypeUnsafeState),
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionViolation {
		t.Fatalf("expected Violation, got %v", row.Decision)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestUnsafeStateStrategy_UnsafeBelowThreshold(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(2 * time.Hour)

	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(time.Hour), true},
	})

	s := &unsafeStateStrategy{
		runner: testRunner(4*time.Hour, now),
		ctl:    testControl("CTL.STATE.001", policy.TypeUnsafeState),
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionPass {
		t.Fatalf("expected Pass (below threshold), got %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// unsafeDurationStrategy
// ---------------------------------------------------------------------------

func TestUnsafeDurationStrategy_SafeAsset(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(24 * time.Hour)

	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
		{base.Add(6 * time.Hour), false},
		{base.Add(12 * time.Hour), false},
	})

	s := &unsafeDurationStrategy{
		runner: testRunner(4*time.Hour, now),
		ctl:    testControl("CTL.DUR.001", policy.TypeUnsafeDuration),
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionPass {
		t.Fatalf("expected Pass, got %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestUnsafeDurationStrategy_ViolationExceedsThreshold(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(6 * time.Hour)

	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, true},
		{base.Add(time.Hour), true},
	})

	s := &unsafeDurationStrategy{
		runner: testRunner(4*time.Hour, now),
		ctl:    testControl("CTL.DUR.001", policy.TypeUnsafeDuration),
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionViolation {
		t.Fatalf("expected Violation, got %v", row.Decision)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestUnsafeDurationStrategy_InconclusiveInsufficientCoverage(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)

	// Single observation — not enough span for the 168h threshold
	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
	})

	s := &unsafeDurationStrategy{
		runner: testRunner(168*time.Hour, now),
		ctl:    testControl("CTL.DUR.001", policy.TypeUnsafeDuration),
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionInconclusive {
		t.Fatalf("expected Inconclusive (insufficient coverage), got %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for inconclusive, got %d", len(findings))
	}
}

func TestUnsafeDurationStrategy_SafeWithAdequateCoverage(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(6 * time.Hour)

	// 3 safe observations spread over 5 hours — exceeds 4h threshold
	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
		{base.Add(2 * time.Hour), false},
		{base.Add(5 * time.Hour), false},
	})

	s := &unsafeDurationStrategy{
		runner: testRunner(4*time.Hour, now),
		ctl:    testControl("CTL.DUR.001", policy.TypeUnsafeDuration),
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionPass {
		t.Fatalf("expected Pass with adequate coverage, got %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// unsafeRecurrenceStrategy
// ---------------------------------------------------------------------------

func TestUnsafeRecurrenceStrategy_DisabledPolicy(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)

	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
	})

	// Control without recurrence parameters → policy not enabled
	ctl := testControl("CTL.REC.001", policy.TypeUnsafeRecurrence)

	s := &unsafeRecurrenceStrategy{
		runner: testRunner(4*time.Hour, now),
		ctl:    ctl,
	}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionPass {
		t.Fatalf("expected Pass (disabled recurrence), got %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// unsupportedStrategy
// ---------------------------------------------------------------------------

func TestUnsupportedStrategy_ReturnsSkipped(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)

	tl := buildTimeline(t, []struct {
		at     time.Time
		unsafe bool
	}{
		{base, false},
	})

	ctl := testControl("CTL.AUTH.001", policy.TypeAuthorizationBoundary)
	s := &unsupportedStrategy{ctl: ctl}

	row, findings := s.Evaluate(tl, now)
	if row.Decision != evaluation.DecisionSkipped {
		t.Fatalf("expected Skipped, got %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	if row.Reason == "" {
		t.Fatal("expected non-empty reason for unsupported strategy")
	}
}

// ---------------------------------------------------------------------------
// wrapInPointers
// ---------------------------------------------------------------------------

func TestWrapInPointers_Empty(t *testing.T) {
	result := wrapInPointers(nil)
	if result != nil {
		t.Fatalf("expected nil for empty input, got %v", result)
	}
}

func TestWrapInPointers_NonEmpty(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: "CTL.A.001"},
		{ControlID: "CTL.B.001"},
	}
	result := wrapInPointers(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 pointers, got %d", len(result))
	}
	if result[0].ControlID != "CTL.A.001" {
		t.Fatalf("expected CTL.A.001, got %v", result[0].ControlID)
	}
}
