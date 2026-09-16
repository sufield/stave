package engine

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestPartitionIndeterminate_SuppressedIndeterminateStaysConfirmed(t *testing.T) {
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			Status:    evaluation.FindingSuppressed,
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{
					{Property: predicate.NewFieldPath("p.x"), FieldAbsent: true, Operator: predicate.OpEq},
				},
			},
		},
		{
			ControlID: "CTL.B.001",
			Status:    evaluation.FindingActive,
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{
					{Property: predicate.NewFieldPath("p.y"), FieldAbsent: true, Operator: predicate.OpEq},
				},
			},
		},
		{
			ControlID: "CTL.C.001",
			Status:    evaluation.FindingActive,
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{
					{Property: predicate.NewFieldPath("p.z"), FieldAbsent: false, Operator: predicate.OpEq},
				},
			},
		},
	}

	confirmed, indeterminate := partitionIndeterminateFindings(findings)

	if len(confirmed) != 2 {
		t.Fatalf("expected 2 confirmed (suppressed-indeterminate + active-confirmed), got %d", len(confirmed))
	}
	if len(indeterminate) != 1 {
		t.Fatalf("expected 1 indeterminate (active-indeterminate only), got %d", len(indeterminate))
	}

	suppIndet := confirmed[0]
	if suppIndet.ControlID != "CTL.A.001" {
		t.Fatalf("expected CTL.A.001 first in confirmed, got %v", suppIndet.ControlID)
	}
	if suppIndet.DataQuality != evaluation.DataQualityIndeterminate {
		t.Fatalf("suppressed-indeterminate: expected DataQuality=%q, got %q",
			evaluation.DataQualityIndeterminate, suppIndet.DataQuality)
	}
	if suppIndet.Status != evaluation.FindingSuppressed {
		t.Fatalf("suppressed-indeterminate: expected Status=%q, got %q",
			evaluation.FindingSuppressed, suppIndet.Status)
	}

	if indeterminate[0].ControlID != "CTL.B.001" {
		t.Fatalf("expected CTL.B.001 in indeterminate, got %v", indeterminate[0].ControlID)
	}
}
