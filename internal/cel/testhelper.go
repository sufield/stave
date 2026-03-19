package cel

import "github.com/sufield/stave/internal/domain/policy"

// MustPredicateEval returns a policy.PredicateEval backed by CEL.
// Panics on initialization error. Intended for test code.
func MustPredicateEval() policy.PredicateEval {
	eval, err := NewPredicateEval()
	if err != nil {
		panic("cel.MustPredicateEval: " + err.Error())
	}
	return eval
}
