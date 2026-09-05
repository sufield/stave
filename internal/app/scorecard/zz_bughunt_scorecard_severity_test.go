package scorecard

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_Scorecard_PrefersCriticalFindings(t *testing.T) {
	// A control CTL.A.001 has two findings:
	// 1. low severity on asset-1
	// 2. critical severity on asset-2
	findings := []remediation.Finding{
		{
			ControlID:       kernel.ControlID("CTL.A.001"),
			AssetID:         "asset-1",
			ControlSeverity: policy.SeverityLow,
			ControlCompliance: policy.ComplianceMapping{
				"hipaa": "164.312",
			},
		},
		{
			ControlID:       kernel.ControlID("CTL.A.001"),
			AssetID:         "asset-2",
			ControlSeverity: policy.SeverityCritical,
			ControlCompliance: policy.ComplianceMapping{
				"hipaa": "164.312",
			},
		},
	}

	report := Compute(findings, []policy.ComplianceFramework{"hipaa"})
	if len(report.Frameworks) != 1 {
		t.Fatalf("expected 1 framework score, got %d", len(report.Frameworks))
	}

	f := report.Frameworks[0]
	// Under the buggy code: since the first finding in the slice is Low,
	// the deduplication retains the Low finding, resulting in CriticalFindings = 0.
	// Under correct behavior: it should recognize that the control has a critical finding
	// and set CriticalFindings = 1.
	if f.CriticalFindings != 1 {
		t.Errorf("expected CriticalFindings to be 1, got %d (ignored critical finding because low finding came first)", f.CriticalFindings)
	}
}

func TestBugHunt_Scorecard_HeadlinePrefersHighestSeverity(t *testing.T) {
	findings := []remediation.Finding{
		{
			ControlID:       kernel.ControlID("CTL.LOW.001"),
			AssetID:         "asset-1",
			ControlSeverity: policy.SeverityLow,
			ControlCompliance: policy.ComplianceMapping{
				"hipaa": "164.312",
			},
		},
		{
			ControlID:       kernel.ControlID("CTL.HIGH.001"),
			AssetID:         "asset-2",
			ControlSeverity: policy.SeverityHigh,
			ControlCompliance: policy.ComplianceMapping{
				"hipaa": "164.312",
			},
		},
	}

	report := Compute(findings, []policy.ComplianceFramework{"hipaa"})
	if len(report.Frameworks) != 1 {
		t.Fatalf("expected 1 framework score, got %d", len(report.Frameworks))
	}

	f := report.Frameworks[0]
	// CTL.HIGH.001 has High severity, CTL.LOW.001 has Low severity.
	// Since there are no Critical findings, the headline finding/next action should be CTL.HIGH.001
	// because High is the highest severity present.
	if f.NextAction != "CTL.HIGH.001" {
		t.Errorf("expected NextAction to be 'CTL.HIGH.001', got %q", f.NextAction)
	}
}
