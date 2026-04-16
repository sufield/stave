package compare

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func pFinding(ctl string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			AssetID:         asset.ID("asset-1"),
			ControlSeverity: sev,
		},
	}
}

func TestParity_ConsistentFail(t *testing.T) {
	result := AnalyzeParity(ParityInput{
		EnvOrder: []string{"prod", "staging"},
		Environments: map[string][]remediation.Finding{
			"prod":    {pFinding("CTL.A.001", policy.SeverityCritical)},
			"staging": {pFinding("CTL.A.001", policy.SeverityCritical)},
		},
	})
	if len(result.ConsistentFail) != 1 {
		t.Errorf("consistent fail = %d, want 1", len(result.ConsistentFail))
	}
}

func TestParity_ProdRegression(t *testing.T) {
	result := AnalyzeParity(ParityInput{
		EnvOrder: []string{"prod", "staging"},
		Environments: map[string][]remediation.Finding{
			"prod":    {pFinding("CTL.A.001", policy.SeverityHigh)},
			"staging": {},
		},
	})
	if len(result.ProdRegression) != 1 {
		t.Errorf("prod regression = %d, want 1", len(result.ProdRegression))
	}
}

func TestParity_EnvHardening(t *testing.T) {
	result := AnalyzeParity(ParityInput{
		EnvOrder: []string{"prod", "staging", "dev"},
		Environments: map[string][]remediation.Finding{
			"prod":    {},
			"staging": {pFinding("CTL.A.001", policy.SeverityMedium)},
			"dev":     {pFinding("CTL.A.001", policy.SeverityMedium)},
		},
	})
	if len(result.EnvHardening) != 1 {
		t.Errorf("env hardening = %d, want 1", len(result.EnvHardening))
	}
}
