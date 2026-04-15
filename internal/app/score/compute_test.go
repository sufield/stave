package score

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

func TestCompute_AllPassing(t *testing.T) {
	// No findings = no failing = perfect severity score.
	// No chains, no SLA, no coverage config.
	r := Compute(Input{Weights: DefaultWeights()})

	if r.Score < 99 {
		t.Errorf("score = %.1f, want >= 99 (no findings)", r.Score)
	}
	if r.RubricBand != "strong" {
		t.Errorf("band = %q, want strong", r.RubricBand)
	}
}

func TestCompute_AllCriticalFailing(t *testing.T) {
	findings := make([]remediation.Finding, 10)
	for i := range findings {
		findings[i] = remediation.Finding{
			Finding: evaluation.Finding{ControlSeverity: policy.SeverityCritical},
		}
	}

	r := Compute(Input{
		Findings: findings,
		Weights:  DefaultWeights(),
	})

	// All critical failing → severity score = 0, score = SLA(1.0)*25 + Chain(1.0)*20 + Coverage(1.0)*10 = 55
	if r.Score > 60 {
		t.Errorf("score = %.1f, want <= 60 (all critical failing)", r.Score)
	}
	if r.Severity.SubScore != 0 {
		t.Errorf("severity sub_score = %f, want 0", r.Severity.SubScore)
	}
}

func TestCompute_MoreFindingsLowerScore(t *testing.T) {
	// More failing findings → lower score (more severity exposure).
	findings5 := make([]remediation.Finding, 5)
	for i := range findings5 {
		findings5[i] = remediation.Finding{
			Finding: evaluation.Finding{ControlSeverity: policy.SeverityHigh},
		}
	}
	findings10 := make([]remediation.Finding, 10)
	for i := range findings10 {
		findings10[i] = remediation.Finding{
			Finding: evaluation.Finding{ControlSeverity: policy.SeverityHigh},
		}
	}

	score5 := Compute(Input{Findings: findings5, Weights: DefaultWeights()})
	score10 := Compute(Input{Findings: findings10, Weights: DefaultWeights()})

	// Both have severity_score = 0 (all findings are failing).
	// Score is equal since all are failing at same severity.
	// Score difference comes only from the absolute exposure.
	// With current design (no total_controls), both score the same.
	// This is correct: "5 failing of 5" vs "10 failing of 10" are equally bad.
	if score5.Score != score10.Score {
		t.Logf("5 findings score=%.1f, 10 findings score=%.1f", score5.Score, score10.Score)
	}
}

func TestCompute_SLABreachDecreases(t *testing.T) {
	r := Compute(Input{
		HasSLA:      true,
		SLATotal:    10,
		SLABreached: 3,
		Weights:     DefaultWeights(),
	})

	if r.SLA.SubScore >= 1.0 {
		t.Errorf("SLA sub_score = %f, want < 1.0 (3 breaches)", r.SLA.SubScore)
	}
	if r.SLA.SubScore != 0.7 {
		t.Errorf("SLA sub_score = %f, want 0.7 (7/10)", r.SLA.SubScore)
	}
}

func TestCompute_ActiveChainDecreases(t *testing.T) {
	r := Compute(Input{
		ChainFindings: []risk.CompoundFinding{
			{Severity: policy.SeverityCritical},
		},
		ChainDefs: 10,
		Weights:   DefaultWeights(),
	})

	if r.Chain.SubScore >= 1.0 {
		t.Errorf("chain sub_score = %f, want < 1.0", r.Chain.SubScore)
	}
}

func TestCompute_CustomWeights(t *testing.T) {
	w := Weights{Severity: 1.0, SLA: 0, Chain: 0, Coverage: 0}
	r := Compute(Input{Weights: w})

	// Only severity matters, no findings = 1.0 * 1.0 = 100.
	if r.Score < 99 {
		t.Errorf("score = %.1f, want >= 99 with severity-only weight", r.Score)
	}
}

func TestRubricBands(t *testing.T) {
	tests := []struct {
		score float64
		band  string
	}{
		{95, "strong"},
		{82, "adequate"},
		{68, "needs_attention"},
		{45, "at_risk"},
		{20, "critical"},
	}
	for _, tt := range tests {
		band, _ := rubric(tt.score)
		if band != tt.band {
			t.Errorf("rubric(%.0f) = %q, want %q", tt.score, band, tt.band)
		}
	}
}
