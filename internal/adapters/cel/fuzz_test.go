package cel

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func FuzzCompile(f *testing.F) {
	// Seed with valid and invalid field/op/value combinations.
	f.Add("public", "eq", "true")
	f.Add("", "", "")
	f.Add("properties.encryption.algorithm", "ne", "aws:kms")
	f.Add("a.b.c.d.e", "contains", "x")
	f.Add("field", "missing", "true")
	f.Add("field", "INVALID_OP", "value")
	f.Add(string(make([]byte, 256)), "eq", string(make([]byte, 256)))

	compiler, err := NewCompiler()
	if err != nil {
		f.Fatalf("create compiler: %v", err)
	}

	f.Fuzz(func(t *testing.T, field, op, value string) {
		pred := policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{
					Field: predicate.NewFieldPath(field),
					Op:    predicate.Operator(op),
					Value: policy.NewOperand(value),
				},
			},
		}
		// Must not panic on any input.
		_, _ = compiler.Compile(pred)
	})
}
