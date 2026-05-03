package risk

import (
	stavecel "github.com/sufield/stave/internal/adapters/cel"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func mustPredicateEval() policy.PredicateEval {
	return stavecel.MustPredicateEval()
}
