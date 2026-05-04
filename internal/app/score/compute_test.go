package score

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

func TestCompute_AllPassing(t *testing.T) {
	// No findings = no failing = perfect severity score.
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

func TestCompute_FixingFindingIncreasesScore(t *testing.T) {
	// Monotone property: fixing any finding must increase the score.
	// Environment has 100 total evaluations (TotalCheckWeight = 200).
	// 5 critical + 5 high are currently failing.
	allFindings := make([]remediation.Finding, 10)
	for i := range 5 {
		allFindings[i] = remediation.Finding{
			Finding: evaluation.Finding{ControlSeverity: policy.SeverityCritical},
		}
	}
	for i := 5; i < 10; i++ {
		allFindings[i] = remediation.Finding{
			Finding: evaluation.Finding{ControlSeverity: policy.SeverityHigh},
		}
	}

	totalWeight := 200.0 // passing checks contribute to denominator

	scoreBefore := Compute(Input{
		Findings:         allFindings,
		TotalCheckWeight: totalWeight,
		Weights:          DefaultWeights(),
	})

	// Fix one critical finding (remove it from the violations list).
	fewerFindings := allFindings[1:]
	scoreAfter := Compute(Input{
		Findings:         fewerFindings,
		TotalCheckWeight: totalWeight, // denominator stays same
		Weights:          DefaultWeights(),
	})

	if scoreAfter.Score <= scoreBefore.Score {
		t.Errorf("fixing a finding did not increase score: before=%.1f, after=%.1f",
			scoreBefore.Score, scoreAfter.Score)
	}
}

func TestCompute_AddingPassingControlsDoesNotDecreaseScore(t *testing.T) {
	// Catalog expansion property: adding 30 passing controls grows the
	// denominator (TotalCheckWeight) while violations stay the same,
	// so severity score stays stable or improves.
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityHigh}},
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityMedium}},
	}
	// Violation weight = 4 + 2 = 6
	baseWeight := 50.0 // 50 total evaluations

	scoreBefore := Compute(Input{
		Findings:         findings,
		TotalCheckWeight: baseWeight,
		Weights:          DefaultWeights(),
	})

	// Add 30 passing controls (each medium = 2.0 weight).
	expandedWeight := baseWeight + 30*2.0

	scoreAfter := Compute(Input{
		Findings:         findings,       // same violations
		TotalCheckWeight: expandedWeight, // larger denominator
		Weights:          DefaultWeights(),
	})

	if scoreAfter.Score < scoreBefore.Score {
		t.Errorf("adding passing controls decreased score: before=%.1f, after=%.1f",
			scoreBefore.Score, scoreAfter.Score)
	}
	if scoreAfter.Severity.SubScore < scoreBefore.Severity.SubScore {
		t.Errorf("severity sub_score decreased: before=%.4f, after=%.4f",
			scoreBefore.Severity.SubScore, scoreAfter.Severity.SubScore)
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
	if r.SLA.Detail.FindingsBreached != 3 {
		t.Errorf("SLA detail breached = %d, want 3", r.SLA.Detail.FindingsBreached)
	}
	if r.SLA.Detail.FindingsWithSLA != 10 {
		t.Errorf("SLA detail total = %d, want 10", r.SLA.Detail.FindingsWithSLA)
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
	if r.Chain.Detail.ActiveChains != 1 {
		t.Errorf("chain detail active = %d, want 1", r.Chain.Detail.ActiveChains)
	}
	if r.Chain.Detail.TotalChains != 10 {
		t.Errorf("chain detail total = %d, want 10", r.Chain.Detail.TotalChains)
	}
}

func TestCompute_CustomWeights(t *testing.T) {
	w := Weights{Severity: 1.0, SLA: 0, Chain: 0, Coverage: 0}
	r := Compute(Input{Weights: w})

	// Only severity matters, no findings = 1.0 * 1.0 = 100.
	if r.Score < 99 {
		t.Errorf("score = %.1f, want >= 99 with severity-only weight", r.Score)
	}
	if r.WeightsUsed.Severity != 1.0 {
		t.Errorf("weights_used.severity = %f, want 1.0", r.WeightsUsed.Severity)
	}
}

func TestCompute_WeightsOverrideProducesCorrectSum(t *testing.T) {
	// All components at 0.5 sub-score with equal weights.
	findings := make([]remediation.Finding, 2)
	findings[0] = remediation.Finding{
		Finding: evaluation.Finding{ControlSeverity: policy.SeverityLow},
	}
	// 1 finding failing out of 1 = severity 0.

	w := Weights{Severity: 0.25, SLA: 0.25, Chain: 0.25, Coverage: 0.25}
	r := Compute(Input{
		Findings:    findings,
		HasSLA:      true,
		SLATotal:    2,
		SLABreached: 1, // SLA = 0.5
		ChainFindings: []risk.CompoundFinding{
			{Severity: policy.SeverityHigh},
		},
		ChainDefs:   2, // chainMax=20, active=4 → chainScore = 1 - 4/20 = 0.8
		HasCoverage: true,
		CoveragePct: 50.0, // coverage = 0.5
		Weights:     w,
	})

	// Verify weights are preserved.
	if r.WeightsUsed.SLA != 0.25 {
		t.Errorf("weights_used.sla = %f, want 0.25", r.WeightsUsed.SLA)
	}
	// Verify score is reasonable (not 0 or 100).
	if r.Score <= 0 || r.Score >= 100 {
		t.Errorf("score = %.1f, want between 0 and 100", r.Score)
	}
}

func TestCompute_DetailFields(t *testing.T) {
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityCritical}},
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityHigh}},
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityLow}},
	}

	r := Compute(Input{
		Findings:  findings,
		ChainDefs: 5,
		Weights:   DefaultWeights(),
	})

	if r.Severity.Detail.TotalViolations != 3 {
		t.Errorf("total_findings = %d, want 3", r.Severity.Detail.TotalViolations)
	}
	if r.Severity.Detail.FailingFindings != 3 {
		t.Errorf("failing_findings = %d, want 3", r.Severity.Detail.FailingFindings)
	}
	// MaxRiskExposure = NormalizedWeight(critical+high+low) = 4 + 3 + 1 = 8
	if r.Severity.Detail.MaxRiskExposure != 8 {
		t.Errorf("max_risk_exposure = %f, want 8", r.Severity.Detail.MaxRiskExposure)
	}
	if r.Severity.Detail.ActualExposure != 8 {
		t.Errorf("actual_exposure = %f, want 8 (all failing)", r.Severity.Detail.ActualExposure)
	}
}

func TestCompute_GeneratedAtAndSnapshotID(t *testing.T) {
	ts := time.Date(2025, 11, 15, 14, 23, 0, 0, time.UTC)
	r := Compute(Input{
		Weights:     DefaultWeights(),
		GeneratedAt: ts,
		SnapshotID:  "snap-20251115",
	})

	if !r.GeneratedAt.Equal(ts) {
		t.Errorf("generated_at = %v, want %v", r.GeneratedAt, ts)
	}
	if r.SnapshotID != "snap-20251115" {
		t.Errorf("snapshot_id = %q, want snap-20251115", r.SnapshotID)
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

func TestParseWeights(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		check   func(Weights) bool
	}{
		{"", false, func(w Weights) bool { return w == DefaultWeights() }},
		{"severity=0.60,sla=0.20,chain=0.15,coverage=0.05", false, func(w Weights) bool {
			return w.Severity == 0.60 && w.SLA == 0.20 && w.Chain == 0.15 && w.Coverage == 0.05
		}},
		{"severity=1.0,sla=0,chain=0,coverage=0", false, func(w Weights) bool {
			return w.Severity == 1.0 && w.SLA == 0 && w.Chain == 0 && w.Coverage == 0
		}},
		// Partial overrides that drive the sum away from 1 now fail
		// validation — ParseWeights enforces the sum-to-1 invariant
		// rather than silently letting downstream score arithmetic
		// distort.
		{"severity=1.0", true, nil},
		{"bad", true, nil},
		{"unknown=0.5", true, nil},
		{"severity=notanumber", true, nil},
	}

	for _, tt := range tests {
		w, err := ParseWeights(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseWeights(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			continue
		}
		if tt.check != nil && !tt.check(w) {
			t.Errorf("ParseWeights(%q): unexpected weights %+v", tt.input, w)
		}
	}
}

func TestCompute_CoverageImpact(t *testing.T) {
	// Coverage at 50% should produce coverage sub_score = 0.5.
	r := Compute(Input{
		HasCoverage: true,
		CoveragePct: 50.0,
		Weights:     DefaultWeights(),
	})

	if r.Coverage.SubScore != 0.5 {
		t.Errorf("coverage sub_score = %f, want 0.5", r.Coverage.SubScore)
	}
	if r.Coverage.Detail.CoveragePct != 50.0 {
		t.Errorf("coverage detail pct = %f, want 50.0", r.Coverage.Detail.CoveragePct)
	}
}

func TestCompute_SeverityScore_ZeroTotalWeight_FallbackUsesAvgSeverity(t *testing.T) {
	// Fallback path: TotalCheckWeight unavailable. Previously this
	// collapsed to severity score 0 regardless of finding severity.
	// On the NormalizedWeight (1—4) ladder, Low-only findings score
	// 1 - 1/4 = 0.75; Critical-only score 0.
	low := []remediation.Finding{
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityLow}},
	}
	rLow := Compute(Input{Findings: low, Weights: DefaultWeights()})
	if rLow.Severity.SubScore < 0.7 {
		t.Errorf("low-only fallback severity = %.3f, want >= 0.7", rLow.Severity.SubScore)
	}

	crit := []remediation.Finding{
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityCritical}},
	}
	rCrit := Compute(Input{Findings: crit, Weights: DefaultWeights()})
	if rCrit.Severity.SubScore != 0 {
		t.Errorf("critical-only fallback severity = %.3f, want 0", rCrit.Severity.SubScore)
	}
}

func TestCompute_SeverityScore_NegativeTotalWeight_ClampsTo01(t *testing.T) {
	// Adversarial input: a negative TotalCheckWeight would have driven
	// 1 - (exposure/-N) past 1.0 before clamping, which then displayed
	// as a rubric band not in the catalog.
	r := Compute(Input{
		Findings: []remediation.Finding{
			{Finding: evaluation.Finding{ControlSeverity: policy.SeverityHigh}},
		},
		TotalCheckWeight: -100,
		Weights:          DefaultWeights(),
	})
	if r.Severity.SubScore < 0 || r.Severity.SubScore > 1 {
		t.Errorf("severity sub_score = %.3f, want in [0, 1]", r.Severity.SubScore)
	}
}

func TestCompute_SeverityScore_WeightLessThanExposure_ClampsToZero(t *testing.T) {
	// TotalCheckWeight underestimates real exposure (catalog drift,
	// truncated fixture). 1 - (exposure/weight) goes negative; we
	// clamp to 0 so the worst-possible severity reports as 0, not
	// negative-something that the rubric can't render.
	findings := make([]remediation.Finding, 5)
	for i := range findings {
		findings[i] = remediation.Finding{
			Finding: evaluation.Finding{ControlSeverity: policy.SeverityCritical},
		}
	}
	r := Compute(Input{
		Findings:         findings,
		TotalCheckWeight: 5, // exposure = 5*10 = 50, way bigger than weight
		Weights:          DefaultWeights(),
	})
	if r.Severity.SubScore != 0 {
		t.Errorf("under-counted weight severity = %.3f, want 0", r.Severity.SubScore)
	}
}
