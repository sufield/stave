package cel

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// TestOpListEmpty_AllShapes covers every input shape an extractor
// can put into a properties slot the rule asks `list_empty` against.
//
// Per Phase 11 P11.1 the operator's semantics are:
//
//	absent field          → true
//	empty list/map/string → true
//	non-empty collection  → false
//	non-collection (int/bool/number) → true (logically empty)
//
// The non-collection case is the load-bearing one: an upstream
// extractor that emits an int where a list was expected used to
// surface as a CEL runtime error and crash the predicate; now the
// rule short-circuits to "empty" so evaluation stays robust.
func TestOpListEmpty_AllShapes(t *testing.T) {
	t.Parallel()

	compiler, err := NewCompiler()
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{{
			Field: predicate.NewFieldPath("properties.tags"),
			Op:    predicate.OpListEmpty,
		}},
	}
	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	cases := []struct {
		name  string
		props map[string]any
		want  bool
	}{
		{"absent field", map[string]any{}, true},
		{"empty list", map[string]any{"tags": []any{}}, true},
		{"empty map", map[string]any{"tags": map[string]any{}}, true},
		{"empty string", map[string]any{"tags": ""}, true},
		{"non-empty list", map[string]any{"tags": []any{"a"}}, false},
		{"non-empty map", map[string]any{"tags": map[string]any{"k": "v"}}, false},
		{"non-empty string", map[string]any{"tags": "x"}, false},
		// Non-collection types: per the new contract, these are
		// "logically empty." The previous behavior returned false
		// here, which a control author rarely intends.
		{"int", map[string]any{"tags": 0}, true},
		{"int non-zero", map[string]any{"tags": 7}, true},
		{"bool true", map[string]any{"tags": true}, true},
		{"bool false", map[string]any{"tags": false}, true},
		{"float", map[string]any{"tags": 1.5}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := asset.Asset{
				ID:         "asset-test",
				Type:       "test_type",
				Vendor:     "test",
				Properties: tc.props,
			}
			got, err := Evaluate(cp, a, nil, nil)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got != tc.want {
				t.Errorf("Evaluate(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
