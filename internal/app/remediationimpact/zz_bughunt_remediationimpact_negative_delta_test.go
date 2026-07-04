package remediationimpact

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Analyze_NegativeDeltaVerdict(t *testing.T) {
	// Let's set up a scenario where posture score goes DOWN.
	// before: 10 violations out of 100 assets (score = 90)
	before := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 10},
		Findings: []remediation.Finding{
			finding("CTL.A.001", "asset1", policy.SeverityHigh),
		},
	}
	// after: 20 violations out of 100 assets (score = 80)
	after := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 20},
		Findings: []remediation.Finding{
			finding("CTL.A.001", "asset1", policy.SeverityHigh),
			finding("CTL.B.001", "asset2", policy.SeverityHigh),
		},
	}

	// Suppose predicted delta was also negative: -5.0 (posture worsening predicted)
	// realized delta: 80 - 90 = -10.0
	r, err := Analyze(Input{
		Before:         before,
		After:          after,
		PredictedDelta: -5.0,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if r.ScoreDelta >= 0 {
		t.Fatalf("expected negative score delta, got %f", r.ScoreDelta)
	}

	// Under the buggy code: ratio = -10 / -5 = 2.0. Since 2.0 >= 0.9, verdict = VerdictComplete.
	// Under correct behavior: if posture worsened (realized delta <= 0), it should be VerdictIncomplete.
	if r.Efficiency.Verdict != VerdictIncomplete {
		t.Errorf("expected VerdictIncomplete for worsening posture, got %q (ratio = %f)", r.Efficiency.Verdict, r.Efficiency.Ratio)
	}
}
