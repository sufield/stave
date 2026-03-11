package safetyenvelope

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestNewEvaluation_NormalizesSlices(t *testing.T) {
	got := NewEvaluation(EvaluationRequest{
		Run:                evaluation.RunInfo{},
		Summary:            evaluation.Summary{},
		Findings:           nil,
		Skipped:            nil,
		SkippedAssets:      nil,
		SuppressedFindings: nil,
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
	if got.SuppressedFindings == nil {
		t.Fatal("SuppressedFindings should be normalized to empty slice")
	}
	if got.Skipped == nil {
		t.Fatal("Skipped should be normalized to empty slice")
	}
	if got.SkippedAssets == nil {
		t.Fatal("SkippedAssets should be normalized to empty slice")
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
		Entries: []diagnosis.Entry{
			{
				Case:     diagnosis.EmptyFindings,
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
	if out.Report.Entries == nil {
		t.Fatal("entries should be normalized to empty slice")
	}

	out.Report.Entries[0].Signal = "changed"
	if in.Entries[0].Signal != "signal" {
		t.Fatalf("input report was mutated: got %q", in.Entries[0].Signal)
	}
}
