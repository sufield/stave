package score

import "testing"

// TestBugHunt_CoverageZeroPctMover proves that Result.Movers() drops
// the worst-possible coverage case: a framework with genuinely 0%
// coverage (HasCoverage=true, CoveragePct=0) loses the full coverage
// weight in points (SubScore=0) yet is NOT reported as a score mover.
//
// The other three movers (severity/sla/chain) gate only on a positive
// bad-count and DO report their max-impact case. Coverage should be
// symmetric: any component that lost points (SubScore < 1.0) belongs in
// Movers with PointsLost = MaxContribution - Contribution.
//
// The buggy gate at compute.go:265 is:
//
//	r.Coverage.SubScore < 1.0 && r.Coverage.Detail.CoveragePct > 0
//
// The extra `&& CoveragePct > 0` clause suppresses the 0% case even
// though it loses the most points.
func TestBugHunt_CoverageZeroPctMover(t *testing.T) {
	// 0% coverage: SubScore = 0/100 = 0, which is the maximum coverage
	// impact possible. With DefaultWeights (coverage=0.10) the coverage
	// component loses its full 10 points (MaxContribution=10,
	// Contribution=0).
	r := Compute(Input{
		HasCoverage: true,
		CoveragePct: 0.0,
		Weights:     DefaultWeights(),
	})

	// Sanity: the component genuinely lost its points.
	if r.Coverage.SubScore != 0 {
		t.Fatalf("precondition: coverage sub_score = %f, want 0 (0%% coverage)", r.Coverage.SubScore)
	}
	wantPointsLost := r.Coverage.MaxContribution - r.Coverage.Contribution
	if wantPointsLost <= 0 {
		t.Fatalf("precondition: coverage points lost = %f, want > 0", wantPointsLost)
	}

	// The correct behavior: the coverage component that lost the most
	// points must appear in Movers.
	var coverageMover *ScoreMover
	for i := range r.Movers() {
		if r.Movers()[i].Component == "coverage" {
			m := r.Movers()[i]
			coverageMover = &m
			break
		}
	}

	if coverageMover == nil {
		t.Fatalf("Movers() did not include a coverage mover for 0%% coverage; "+
			"the 0%% case loses the full coverage weight (%.1f pts) but was suppressed "+
			"by the `&& CoveragePct > 0` gate at compute.go:265", wantPointsLost)
	}

	if coverageMover.PointsLost != wantPointsLost {
		t.Fatalf("coverage mover PointsLost = %f, want %f (MaxContribution - Contribution)",
			coverageMover.PointsLost, wantPointsLost)
	}
}
