package remediationimpact

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func finding(ctl string, ast string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		ControlID:       kernel.ControlID(ctl),
		AssetID:         asset.ID(ast),
		ControlSeverity: sev,
	}
}

func TestAnalyze_ClosedFindingsDetected(t *testing.T) {
	before := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 10},
		Findings: []remediation.Finding{
			finding("CTL.A.001", "asset1", policy.SeverityHigh),
			finding("CTL.B.001", "asset2", policy.SeverityHigh),
		},
	}
	after := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 5},
		Findings: []remediation.Finding{
			finding("CTL.B.001", "asset2", policy.SeverityHigh),
		},
	}

	r, err := Analyze(Input{Before: before, After: after})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if len(r.Closed) != 1 {
		t.Fatalf("closed = %d, want 1", len(r.Closed))
	}
	if r.Closed[0].ControlID != "CTL.A.001" {
		t.Errorf("closed control = %s, want CTL.A.001", r.Closed[0].ControlID)
	}
	if r.ScoreDelta <= 0 {
		t.Errorf("score delta = %.1f, want positive", r.ScoreDelta)
	}
}

func TestAnalyze_EfficiencyRatioComputed(t *testing.T) {
	before := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 20},
		Findings: []remediation.Finding{
			finding("CTL.A.001", "a1", policy.SeverityHigh),
		},
	}
	after := &report.Assessment{
		Summary:  evaluation.ComplianceSummary{TotalAssets: 100, Violations: 10},
		Findings: []remediation.Finding{},
	}

	r, err := Analyze(Input{
		Before:         before,
		After:          after,
		PredictedDelta: 12.0,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if r.Efficiency == nil {
		t.Fatal("efficiency should be computed when PredictedDelta > 0")
	}
	if r.Efficiency.Ratio <= 0 {
		t.Errorf("ratio = %.2f, want > 0", r.Efficiency.Ratio)
	}
	if r.Efficiency.Verdict == "" {
		t.Error("verdict should be set")
	}
}

// TestAnalyze_ChainDeactivationDetected exercises the set-difference
// branch (chains present in Before but absent in After). The branch
// was untested in the pre-untangle test suite; added when the helper
// buildChainSet was inlined so the rewrite has positive coverage.
// findings.CompoundFinding is used here in test setup to populate
// report.Assessment.ChainFindings — the production code path no
// longer names the type explicitly.
func TestAnalyze_ChainDeactivationDetected(t *testing.T) {
	chain := func(id string, sev policy.Severity) findings.CompoundFinding {
		return findings.CompoundFinding{
			ChainID:  kernel.ChainID(id),
			Severity: sev,
		}
	}
	before := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 10, Violations: 3},
		ChainFindings: []findings.CompoundFinding{
			chain("chain.capital-one", policy.SeverityCritical),
			chain("chain.ghost-ref", policy.SeverityHigh),
			chain("chain.persisting", policy.SeverityMedium),
		},
	}
	after := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 10, Violations: 1},
		ChainFindings: []findings.CompoundFinding{
			chain("chain.persisting", policy.SeverityMedium),
		},
	}

	r, err := Analyze(Input{Before: before, After: after})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if len(r.ChainsDeactivated) != 2 {
		t.Fatalf("deactivated chains = %d, want 2", len(r.ChainsDeactivated))
	}
	// Map iteration is non-deterministic; check both expected
	// chain IDs are present without asserting order.
	seen := map[kernel.ChainID]string{}
	for _, d := range r.ChainsDeactivated {
		seen[d.ChainID] = d.PreviousSeverity.String()
	}
	if seen["chain.capital-one"] != "critical" {
		t.Errorf("chain.capital-one severity = %q, want critical", seen["chain.capital-one"])
	}
	if seen["chain.ghost-ref"] != "high" {
		t.Errorf("chain.ghost-ref severity = %q, want high", seen["chain.ghost-ref"])
	}
	if _, present := seen["chain.persisting"]; present {
		t.Error("chain.persisting should not be deactivated (present in After)")
	}
}
