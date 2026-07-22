package score

import (
	"testing"
)

func TestBugHunt_Score_CoverageSubscoreClamping(t *testing.T) {
	// Setup weights where coverage is 10%
	weights, err := NewWeights(0.45, 0.25, 0.20, 0.10)
	if err != nil {
		t.Fatalf("failed to create weights: %v", err)
	}

	// Case 1: CoveragePct > 100.0 (e.g. 120.0%)
	// All other subscores are 1.0 (perfect).
	// If coverage is not clamped, total score = 0.45*1 + 0.25*1 + 0.20*1 + 0.10*1.2 = 1.02 (102%)
	r1 := Compute(Input{
		HasCoverage: true,
		CoveragePct: 120.0,
		Weights:     weights,
	})

	if r1.Coverage.SubScore > 1.0 {
		t.Errorf("expected coverage subscore to be clamped to 1.0, got %f", r1.Coverage.SubScore)
	}
	if r1.Score > 100.0 {
		t.Errorf("expected final posture score to not exceed 100.0, got %f", r1.Score)
	}

	// Case 2: CoveragePct < 0.0 (e.g. -50.0%)
	// All other subscores are 1.0 (perfect).
	// If coverage is not clamped, total score = 0.45*1 + 0.25*1 + 0.20*1 + 0.10*(-0.5) = 0.85 (85%)
	r2 := Compute(Input{
		HasCoverage: true,
		CoveragePct: -50.0,
		Weights:     weights,
	})

	if r2.Coverage.SubScore < 0.0 {
		t.Errorf("expected coverage subscore to be clamped to 0.0, got %f", r2.Coverage.SubScore)
	}
	if r2.Score < 90.0 {
		t.Errorf("expected final posture score to not drop below 90.0 (since coverage contribution is 0%%), got %f", r2.Score)
	}
}
