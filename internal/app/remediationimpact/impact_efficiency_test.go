package remediationimpact

import (
	"math"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/report"
)

// assessmentWith builds an assessment whose simple score is
// (1 - violations/totalAssets) * 100.
func assessmentWith(totalAssets, violations int) *report.Assessment {
	return &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: totalAssets, Violations: violations},
	}
}

func TestComputeSimpleScore_ExactValues(t *testing.T) {
	cases := []struct {
		name        string
		total, viol int
		want        float64
	}{
		{"zero assets is fully compliant", 0, 0, 100},
		{"10 of 100 violating", 100, 10, 90},
		{"half violating", 100, 50, 50},
		{"all violating", 100, 100, 0},
		{"more violations than assets clamps to 0", 100, 200, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := computeSimpleScore(assessmentWith(c.total, c.viol))
			if math.Abs(got-c.want) > 1e-9 {
				t.Fatalf("computeSimpleScore(total=%d, viol=%d) = %.4f, want %.4f",
					c.total, c.viol, got, c.want)
			}
		})
	}
}

// TestAnalyze_EfficiencyMetrics pins the exact RealizedDelta / ScoreDelta /
// Ratio values and the verdict bands (including the 0.5 and 0.9 boundaries
// and the negative-ratio clamp). The existing efficiency test only checked
// Ratio > 0 and Verdict != "", leaving the arithmetic and thresholds unpinned.
func TestAnalyze_EfficiencyMetrics(t *testing.T) {
	// before score 50 (50/100 violating); after varies per case.
	cases := []struct {
		name         string
		afterViol    int     // after assessment violations (total 100)
		predicted    float64 // PredictedDelta
		wantRealized float64
		wantRatio    float64
		wantVerdict  EfficiencyVerdict
	}{
		// after score 90 -> realized 40
		{"partial at ratio 0.8", 10, 50, 40, 0.8, VerdictPartial},
		{"incomplete at ratio 0.4", 10, 100, 40, 0.4, VerdictIncomplete},
		// after score 95 -> realized 45; ratio exactly 0.9 -> Complete (boundary)
		{"complete at ratio 0.9 boundary", 5, 50, 45, 0.9, VerdictComplete},
		// after score 75 -> realized 25; ratio exactly 0.5 -> Partial (boundary)
		{"partial at ratio 0.5 boundary", 25, 50, 25, 0.5, VerdictPartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Analyze(Input{
				Before:         assessmentWith(100, 50),
				After:          assessmentWith(100, c.afterViol),
				PredictedDelta: c.predicted,
			})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if math.Abs(r.ScoreDelta-c.wantRealized) > 1e-9 {
				t.Errorf("ScoreDelta = %.4f, want %.4f", r.ScoreDelta, c.wantRealized)
			}
			if r.Efficiency == nil {
				t.Fatal("Efficiency should be set when PredictedDelta != 0")
			}
			if math.Abs(r.Efficiency.RealizedDelta-c.wantRealized) > 1e-9 {
				t.Errorf("RealizedDelta = %.4f, want %.4f", r.Efficiency.RealizedDelta, c.wantRealized)
			}
			if math.Abs(r.Efficiency.Ratio-c.wantRatio) > 1e-9 {
				t.Errorf("Ratio = %.4f, want %.4f", r.Efficiency.Ratio, c.wantRatio)
			}
			if r.Efficiency.Verdict != c.wantVerdict {
				t.Errorf("Verdict = %q, want %q", r.Efficiency.Verdict, c.wantVerdict)
			}
		})
	}
}

func TestAnalyze_NegativeRatioClampedToZero(t *testing.T) {
	// after worse than before: realized negative -> ratio < 0 -> clamp to 0.
	r, err := Analyze(Input{
		Before:         assessmentWith(100, 10), // score 90
		After:          assessmentWith(100, 50), // score 50
		PredictedDelta: 50,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if r.Efficiency == nil {
		t.Fatal("Efficiency should be set")
	}
	if r.Efficiency.RealizedDelta != -40 {
		t.Errorf("RealizedDelta = %.4f, want -40", r.Efficiency.RealizedDelta)
	}
	if r.Efficiency.Ratio != 0 {
		t.Errorf("Ratio = %.4f, want 0 (negative ratio clamped)", r.Efficiency.Ratio)
	}
	if r.Efficiency.Verdict != VerdictIncomplete {
		t.Errorf("Verdict = %q, want %q", r.Efficiency.Verdict, VerdictIncomplete)
	}
}
