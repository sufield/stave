package safetyenvelope

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestNewEvaluation_NormalizesSlices(t *testing.T) {
	got := NewEvaluation(EvaluationRequest{
		Run:              evaluation.RunInfo{},
		Summary:          evaluation.Summary{},
		Findings:         nil,
		Skipped:          nil,
		ExemptedAssets:   nil,
		ExceptedFindings: nil,
	})

	if got.SchemaVersion != kernel.SchemaOutput {
		t.Fatalf("SchemaVersion = %q, want %q", got.SchemaVersion, kernel.SchemaOutput)
	}
	if got.Kind != KindEvaluation {
		t.Fatalf("Kind = %q, want %q", got.Kind, KindEvaluation)
	}
	if got.Findings == nil {
		t.Fatal("Findings should be normalized to empty slice")
	}
	if got.ExceptedFindings == nil {
		t.Fatal("ExceptedFindings should be normalized to empty slice")
	}
	if got.Skipped == nil {
		t.Fatal("Skipped should be normalized to empty slice")
	}
	if got.ExemptedAssets == nil {
		t.Fatal("ExemptedAssets should be normalized to empty slice")
	}
}

func TestNewVerification_NormalizesSlices(t *testing.T) {
	v := NewVerification(VerificationRequest{})

	if v.SchemaVersion != kernel.SchemaOutput {
		t.Fatalf("SchemaVersion = %q, want %q", v.SchemaVersion, kernel.SchemaOutput)
	}
	if v.Kind != KindVerification {
		t.Fatalf("Kind = %q, want %q", v.Kind, KindVerification)
	}
	if v.Resolved == nil {
		t.Fatal("Resolved should be normalized to empty slice")
	}
	if v.Remaining == nil {
		t.Fatal("Remaining should be normalized to empty slice")
	}
	if v.Introduced == nil {
		t.Fatal("Introduced should be normalized to empty slice")
	}
}

func TestNewDiagnose_DoesNotMutateInput(t *testing.T) {
	in := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{
				Case:     diagnosis.ScenarioEmptyFindings,
				Signal:   "signal",
				Evidence: "evidence",
				Action:   "action",
			},
		},
	}

	out := NewDiagnose(in)
	if out.SchemaVersion != kernel.SchemaDiagnose {
		t.Fatalf("SchemaVersion = %q, want %q", out.SchemaVersion, kernel.SchemaDiagnose)
	}
	if out.Report == in {
		t.Fatal("NewDiagnose should return a copied report pointer")
	}
	if out.Report.Issues == nil {
		t.Fatal("entries should be normalized to empty slice")
	}

	out.Report.Issues[0].Signal = "changed"
	if in.Issues[0].Signal != "signal" {
		t.Fatalf("input report was mutated: got %q", in.Issues[0].Signal)
	}
}
