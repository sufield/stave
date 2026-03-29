package output_test

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/adapters/output"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuildSafetyEnvelopeFromEnriched_NilFindings(t *testing.T) {
	enriched := appcontracts.EnrichedResult{
		Run: evaluation.RunInfo{
			Now:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		},
		Result: evaluation.Result{
			Summary:      evaluation.Summary{AssetsEvaluated: 5},
			SafetyStatus: evaluation.StatusSafe,
		},
		// Findings is nil
	}
	env := output.BuildSafetyEnvelopeFromEnriched(enriched)
	if env == nil {
		t.Fatal("expected non-nil envelope")
	}
	if len(env.Findings) != 0 {
		t.Fatalf("expected empty findings, got %d", len(env.Findings))
	}
}

func TestBuildSafetyEnvelopeFromEnriched_WithFindings(t *testing.T) {
	enriched := appcontracts.EnrichedResult{
		Run: evaluation.RunInfo{
			Now:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		},
		Result: evaluation.Result{
			Summary: evaluation.Summary{
				AssetsEvaluated: 1,
				Violations:      1,
			},
			SafetyStatus: evaluation.StatusUnsafe,
		},
		Findings: []remediation.Finding{
			{Finding: evaluation.Finding{ControlID: "CTL.A.001", AssetID: "bucket-1"}},
		},
	}
	env := output.BuildSafetyEnvelopeFromEnriched(enriched)
	if env == nil {
		t.Fatal("expected non-nil envelope")
	}
	if len(env.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(env.Findings))
	}
}
