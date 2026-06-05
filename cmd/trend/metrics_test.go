package trend

import (
	"math"
	"testing"
)

// Bug 1 — computeVelocity produces NaN -> "steady" when the effective window
// holds a single element (windowSize == 1 with len(runs) >= 2).
//
// The window then has one element, the inner delta loop never runs, totalDelta
// stays 0.0, and avg = 0.0/float64(len(window)-1) = 0.0/0.0 = NaN. Every NaN
// comparison is false, so the function falls through to "steady" instead of the
// correct "insufficient_data".
//
// computeVelocity returns velocityMetrics{WindowRuns, AvgNetChange, Direction}.
func TestComputeVelocity_WindowSizeOne_IsInsufficientData(t *testing.T) {
	runs := []runMetrics{
		{ViolationCount: 10},
		{ViolationCount: 5},
	}

	v := computeVelocity(runs, 1)

	if math.IsNaN(v.AvgNetChange) {
		t.Fatalf("computeVelocity(windowSize=1) AvgNetChange is NaN (0.0/0.0); want a defined value")
	}
	if v.Direction == "steady" {
		t.Fatalf("windowSize=1 classified as %q: NaN comparisons fell through to steady; want %q",
			v.Direction, "insufficient_data")
	}
	if v.Direction != "insufficient_data" {
		t.Fatalf("got Direction=%q for a single-element window, want %q", v.Direction, "insufficient_data")
	}
}

// Bug 7 — computeProjection's target count uses ViolationCount + PassCount
// (findings + compliant assets, two different units) as the denominator,
// instead of TotalAssets — the denominator ViolationRate is actually computed
// against (violations / TotalAssets in computeRunMetrics).
//
// Scenario: 100 assets, 10 of which are each flagged by 3 controls.
//
//	ViolationCount = 30 (findings), PassCount = 90 (compliant assets), TotalAssets = 100
//	ViolationRate  = 30/100 = 0.30  (above the 0.05 target, so a projection is produced)
//	correct target = 0.05 * TotalAssets        = 5  -> runsNeeded (30-5)/1 = 25
//	buggy   target = 0.05 * (Violation+Pass=120) = 6  -> runsNeeded (30-6)/1 = 24
//
// computeProjection(runs, velocityMetrics) returns *projectionMetrics and only
// produces a projection when Direction=="improving" and AvgNetChange < 0.
func TestComputeProjection_UsesTotalAssetsNotFindingSum(t *testing.T) {
	runs := []runMetrics{
		{TotalAssets: 100, ViolationCount: 30, PassCount: 90, ViolationRate: 0.30},
	}
	velocity := velocityMetrics{Direction: "improving", AvgNetChange: -1.0}

	p := computeProjection(runs, velocity)
	if p == nil {
		t.Fatal("expected a projection (improving velocity, rate 0.30 above 0.05 target)")
	}
	if p.EstimatedRuns == 24 {
		t.Fatalf("computeProjection used the findings+assets denominator (EstimatedRuns=24); " +
			"want 25 from TotalAssets")
	}
	if p.EstimatedRuns != 25 {
		t.Fatalf("EstimatedRuns=%d, want 25 (target = targetRate * TotalAssets)", p.EstimatedRuns)
	}
}

// computeVelocity boundary/value coverage: exact average, the +/-0.5
// direction thresholds, a window of exactly two runs, and windowSize == 0
// meaning "use all runs". The original single-scenario test left these
// (and the arithmetic) unpinned.
func TestComputeVelocity_ThresholdsAndWindow(t *testing.T) {
	cases := []struct {
		name       string
		runs       []runMetrics
		windowSize int
		wantAvg    float64
		wantWindow int
		wantDir    string
	}{
		// 2-run window, exact average -4 -> improving.
		{"two-run window exact avg", []runMetrics{{ViolationCount: 10}, {ViolationCount: 6}}, 5, -4, 2, "improving"},
		// avg exactly -0.5 must stay "steady" (threshold is < -0.5, not <=).
		{"avg exactly -0.5 is steady", []runMetrics{{ViolationCount: 10}, {ViolationCount: 10}, {ViolationCount: 9}}, 5, -0.5, 3, "steady"},
		// avg exactly +0.5 must stay "steady" (threshold is > 0.5, not >=).
		{"avg exactly +0.5 is steady", []runMetrics{{ViolationCount: 9}, {ViolationCount: 9}, {ViolationCount: 10}}, 5, 0.5, 3, "steady"},
		// windowSize 0 means no limit: use all runs.
		{"windowSize 0 uses all runs", []runMetrics{{ViolationCount: 10}, {ViolationCount: 5}, {ViolationCount: 2}}, 0, -4, 3, "improving"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := computeVelocity(c.runs, c.windowSize)
			if math.Abs(v.AvgNetChange-c.wantAvg) > 1e-9 {
				t.Errorf("AvgNetChange = %.4f, want %.4f", v.AvgNetChange, c.wantAvg)
			}
			if v.WindowRuns != c.wantWindow {
				t.Errorf("WindowRuns = %d, want %d", v.WindowRuns, c.wantWindow)
			}
			if v.Direction != c.wantDir {
				t.Errorf("Direction = %q, want %q", v.Direction, c.wantDir)
			}
		})
	}
}

// computeProjection guard boundaries: not-improving -> nil, empty runs -> nil,
// latestRate exactly at target -> nil, and zero velocity -> nil.
func TestComputeProjection_GuardBoundaries(t *testing.T) {
	improving := velocityMetrics{Direction: "improving", AvgNetChange: -1.0}

	if p := computeProjection(nil, improving); p != nil {
		t.Errorf("empty runs must yield nil, got %+v", p)
	}
	if p := computeProjection([]runMetrics{{ViolationRate: 0.30}}, velocityMetrics{Direction: "regressing", AvgNetChange: 1}); p != nil {
		t.Errorf("non-improving velocity must yield nil, got %+v", p)
	}
	// latestRate exactly equals the 0.05 target -> already at target -> nil.
	if p := computeProjection([]runMetrics{{ViolationRate: 0.05, ViolationCount: 5, TotalAssets: 100}}, improving); p != nil {
		t.Errorf("rate exactly at target must yield nil, got %+v", p)
	}
	// Zero velocity (Direction improving but AvgNetChange 0) -> nil (no progress).
	zero := velocityMetrics{Direction: "improving", AvgNetChange: 0}
	if p := computeProjection([]runMetrics{{ViolationRate: 0.30, ViolationCount: 30, TotalAssets: 100}}, zero); p != nil {
		t.Errorf("zero velocity must yield nil, got %+v", p)
	}
}

func TestComputeProjection_EstimatedRunsExactAndClamped(t *testing.T) {
	// Exact: target = 0.05*100 = 5; (30-5)/1 = 25.
	exact := computeProjection(
		[]runMetrics{{ViolationRate: 0.30, ViolationCount: 30, TotalAssets: 100}},
		velocityMetrics{Direction: "improving", AvgNetChange: -1.0},
	)
	if exact == nil || exact.EstimatedRuns != 25 {
		t.Fatalf("exact projection EstimatedRuns = %v, want 25", exact)
	}

	// Clamp: target = 5; (6-5)/2 = 0.5 -> int() truncates to 0 -> clamped to 1.
	// Pins both the runsNeeded formula and the `<= 0` clamp boundary.
	clamped := computeProjection(
		[]runMetrics{{ViolationRate: 0.06, ViolationCount: 6, TotalAssets: 100}},
		velocityMetrics{Direction: "improving", AvgNetChange: -2.0},
	)
	if clamped == nil || clamped.EstimatedRuns != 1 {
		t.Fatalf("clamped projection EstimatedRuns = %v, want 1 (truncated 0 clamps to 1)", clamped)
	}
}
