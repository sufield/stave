package diagnosis

import (
	stavecel "github.com/sufield/stave/internal/cel"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func mustPredicateEval() policy.PredicateEval {
	return stavecel.MustPredicateEval()
}
