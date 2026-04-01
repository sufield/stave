package cel

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// NewPredicateEval creates a policy.PredicateEval backed by the CEL engine.
// The returned function compiles predicates on first use and caches them.
func NewPredicateEval() (policy.PredicateEval, error) {
	compiler, err := NewCompiler()
	if err != nil {
		return nil, err
	}
	return func(ctl policy.ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (bool, error) {
		cp, compileErr := compiler.Compile(ctl.UnsafePredicate)
		if compileErr != nil {
			return false, compileErr
		}
		return Evaluate(cp, a, identities, ctl.Params.Raw())
	}, nil
}

// MustPredicateEval creates a PredicateEval or panics. For use in tests only.
func MustPredicateEval() policy.PredicateEval {
	eval, err := NewPredicateEval()
	if err != nil {
		panic("MustPredicateEval: " + err.Error())
	}
	return eval
}
