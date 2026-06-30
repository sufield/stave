package fieldcov

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestBugHunt_Analyze_ShoppingListDeterminism(t *testing.T) {
	// Multiple missing fields for the same asset type and same severity.
	// Since the original code iterates a map to populate the shopping list and doesn't break ties
	// by field name when sorting, the output order is non-deterministic.
	controls := []policy.ControlDefinition{
		{
			ID:       "CTL.A.001",
			Severity: policy.SeverityHigh,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.z_field"), Op: predicate.OpEq},
				},
			},
		},
		{
			ID:       "CTL.B.001",
			Severity: policy.SeverityHigh,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.a_field"), Op: predicate.OpEq},
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  controls,
		Snapshots: nil, // no snapshots, so fields are missing
	})

	list, ok := report.ShoppingList["s3_bucket"]
	if !ok {
		t.Fatalf("expected s3_bucket in shopping list")
	}

	if len(list) != 2 {
		t.Fatalf("expected 2 items, got %d", len(list))
	}

	// We expect the items to be sorted by Field as the tie-breaker: "properties.storage.a_field" then "properties.storage.z_field"
	if list[0].Field != "properties.storage.a_field" {
		t.Errorf("list[0].Field = %q, want properties.storage.a_field", list[0].Field)
	}
	if list[1].Field != "properties.storage.z_field" {
		t.Errorf("list[1].Field = %q, want properties.storage.z_field", list[1].Field)
	}
}

func TestBugHunt_Analyze_ControlResultsDeterminism(t *testing.T) {
	// Controls with the same severity should sort by ControlID as tie-breaker
	controls := []policy.ControlDefinition{
		{
			ID:       "CTL.Z.001",
			Severity: policy.SeverityHigh,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.field"), Op: predicate.OpEq},
				},
			},
		},
		{
			ID:       "CTL.A.001",
			Severity: policy.SeverityHigh,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.field"), Op: predicate.OpEq},
				},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  controls,
		Snapshots: nil,
	})

	if len(report.SilentRisk) != 2 {
		t.Fatalf("expected 2 silent risk controls, got %d", len(report.SilentRisk))
	}

	// We expect the items to be sorted by ControlID as the tie-breaker: "CTL.A.001" then "CTL.Z.001"
	if report.SilentRisk[0].ControlID != "CTL.A.001" {
		t.Errorf("report.SilentRisk[0] = %s, want CTL.A.001", report.SilentRisk[0].ControlID)
	}
	if report.SilentRisk[1].ControlID != "CTL.Z.001" {
		t.Errorf("report.SilentRisk[1] = %s, want CTL.Z.001", report.SilentRisk[1].ControlID)
	}
}
