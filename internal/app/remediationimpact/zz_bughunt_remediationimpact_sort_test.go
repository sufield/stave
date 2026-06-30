package remediationimpact

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Analyze_RemediationImpactDeterminism(t *testing.T) {
	chain := func(id string, sev policy.Severity) findings.CompoundFinding {
		return findings.CompoundFinding{
			ChainID:  kernel.ChainID(id),
			Severity: sev,
		}
	}
	before := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 10, Violations: 3},
		Findings: []remediation.Finding{
			finding("CTL.Z.001", "asset1", policy.SeverityHigh),
			finding("CTL.A.001", "asset2", policy.SeverityHigh),
		},
		ChainFindings: []findings.CompoundFinding{
			chain("chain.z_deactivated", policy.SeverityHigh),
			chain("chain.a_deactivated", policy.SeverityHigh),
		},
	}
	after := &report.Assessment{
		Summary:       evaluation.ComplianceSummary{TotalAssets: 10, Violations: 0},
		Findings:      []remediation.Finding{},
		ChainFindings: []findings.CompoundFinding{},
	}

	r, err := Analyze(Input{Before: before, After: after})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if len(r.Closed) != 2 {
		t.Fatalf("expected 2 closed findings, got %d", len(r.Closed))
	}
	if len(r.ChainsDeactivated) != 2 {
		t.Fatalf("expected 2 deactivated chains, got %d", len(r.ChainsDeactivated))
	}

	// We expect Closed findings to be sorted by ControlID first: CTL.A.001 then CTL.Z.001
	if r.Closed[0].ControlID != "CTL.A.001" {
		t.Errorf("r.Closed[0].ControlID = %s, want CTL.A.001", r.Closed[0].ControlID)
	}
	if r.Closed[1].ControlID != "CTL.Z.001" {
		t.Errorf("r.Closed[1].ControlID = %s, want CTL.Z.001", r.Closed[1].ControlID)
	}

	// We expect ChainsDeactivated to be sorted by ChainID: chain.a_deactivated then chain.z_deactivated
	if r.ChainsDeactivated[0].ChainID != "chain.a_deactivated" {
		t.Errorf("r.ChainsDeactivated[0].ChainID = %s, want chain.a_deactivated", r.ChainsDeactivated[0].ChainID)
	}
	if r.ChainsDeactivated[1].ChainID != "chain.z_deactivated" {
		t.Errorf("r.ChainsDeactivated[1].ChainID = %s, want chain.z_deactivated", r.ChainsDeactivated[1].ChainID)
	}
}
