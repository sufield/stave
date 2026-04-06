package output_test

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/adapters/output"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuildAssessmentFromEnriched_NilFindings(t *testing.T) {
	enriched := appcontracts.EnrichedResult{
		Run: evaluation.RunInfo{
			Now:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		},
		Result: evaluation.ComplianceReport{
			Summary:       evaluation.ComplianceSummary{TotalAssets: 5},
			SecurityState: evaluation.StateCompliant,
		},
		// Findings is nil
	}
	env := output.BuildAssessmentFromEnriched(enriched)
	if env == nil {
		t.Fatal("expected non-nil envelope")
	}
	if len(env.Findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(env.Findings))
	}
}

func TestBuildAssessmentFromEnriched_WithFindings(t *testing.T) {
	enriched := appcontracts.EnrichedResult{
		Run: evaluation.RunInfo{
			Now:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		},
		Result: evaluation.ComplianceReport{
			Summary: evaluation.ComplianceSummary{
				TotalAssets: 1,
				Violations:  1,
			},
			SecurityState: evaluation.StateNonCompliant,
		},
		Findings: []appcontracts.EnrichedFinding{
			{Finding: evaluation.Finding{ControlID: "CTL.A.001", AssetID: "bucket-1"}},
		},
	}
	env := output.BuildAssessmentFromEnriched(enriched)
	if env == nil {
		t.Fatal("expected non-nil envelope")
	}
	if len(env.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(env.Findings))
	}
}
