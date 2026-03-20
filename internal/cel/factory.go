package cel

import (
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
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
		return Evaluate(cp, a, identities)
	}, nil
}
