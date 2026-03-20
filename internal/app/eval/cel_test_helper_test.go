package eval

import (
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

func mustPredicateEval() policy.PredicateEval {
	eval, err := stavecel.NewPredicateEval()
	if err != nil {
		panic("mustPredicateEval: " + err.Error())
	}
	return eval
}
