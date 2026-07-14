package compare

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestBugHunt_Analyze_ZeroTargetViolations_Readiness100(t *testing.T) {
	// Baseline has a violation, but Target has ZERO violations
	findings := []remediation.Finding{
		finding("CTL.A.001", policy.SeverityHigh, map[policy.ComplianceFramework]string{
			"hipaa": "164.312",
		}),
	}

	r := Analyze(Input{
		BaselineKey: "hipaa",
		TargetKey:   "soc2",
		Findings:    findings,
	})

	if r.AdoptionReadiness.ReadinessPct != 100.0 {
		t.Errorf("expected readiness 100.0 when target has zero violations, got %.1f", r.AdoptionReadiness.ReadinessPct)
	}
}
