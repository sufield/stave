package controldef

import (
	"testing"

	"github.com/sufield/stave/internal/core/predicate"
)

func TestBugHunt_ExtractMisconfigurations_ValueFromParam(t *testing.T) {
	t.Parallel()

	// A rule using value_from_param: "min_retention" should resolve the expected unsafe value
	// from the evaluation context parameter "min_retention".
	pred := &UnsafePredicate{
		Any: []PredicateRule{
			{
				Field:          predicate.NewFieldPath("properties.retention_days"),
				Op:             predicate.OpLt,
				ValueFromParam: predicate.ParamRef("min_retention"),
			},
		},
	}

	ctx := &EvalContext{
		properties: map[string]any{"retention_days": 30},
		Params:     NewParams(map[string]any{"min_retention": 90}),
	}

	results := ExtractMisconfigurations(pred, ctx)
	if len(results) != 1 {
		t.Fatalf("expected 1 misconfiguration, got %d", len(results))
	}

	got := results[0].UnsafeValue
	want := 90
	if got != want {
		t.Errorf("UnsafeValue = %v (type %T), want %v (type %T) from parameter", got, got, want, want)
	}
}
