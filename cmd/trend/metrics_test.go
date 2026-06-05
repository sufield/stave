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
