package engine

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

type mockDigester struct{}

func (d mockDigester) Digest(components []string, sep byte) kernel.Digest {
	return kernel.Digest(strings.Join(components, string(sep)))
}

func TestFingerprintPolicy_NonDeterministic(t *testing.T) {
	// A predicate with a map value. fmt.Sprintf("%v", map) is non-deterministic in Go.
	// We need to use any_match which uses maps for nested predicates.

	val := map[string]any{
		"all": []any{
			map[string]any{"field": "a", "op": "eq", "value": "1"},
			map[string]any{"field": "b", "op": "eq", "value": "2"},
			map[string]any{"field": "c", "op": "eq", "value": "3"},
			map[string]any{"field": "d", "op": "eq", "value": "4"},
			map[string]any{"field": "e", "op": "eq", "value": "5"},
		},
	}

	ctl := controldef.ControlDefinition{
		ID:   "CTL.TEST.001",
		Type: controldef.TypeUnsafeState,
		UnsafePredicate: controldef.UnsafePredicate{
			Any: []controldef.PredicateRule{
				{
					Field: predicate.NewFieldPath("identities"),
					Op:    "any_match",
					Value: controldef.NewOperand(val),
				},
			},
		},
	}

	a := &Assessor{
		Controls: []controldef.ControlDefinition{ctl},
		Hasher:   mockDigester{},
	}

	first := a.FingerprintPolicy()
	for i := range 1000 {
		next := a.FingerprintPolicy()
		if next != first {
			t.Errorf("FingerprintPolicy is non-deterministic at iteration %d: %q vs %q", i, first, next)
			return
		}
	}
	// FingerprintPolicy is deterministic — correct behavior after the fix.
}
