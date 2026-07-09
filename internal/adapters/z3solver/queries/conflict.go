//go:build cgo && z3

package queries

import (
	"fmt"
	"time"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/internal/adapters/z3solver/compiler"
)

// QueryConflict answers "Do the loaded policies contradict each other?".
func QueryConflict(model *compiler.CompiledModel) *QueryResult {
	start := time.Now()

	r := &QueryResult{
		QueryName: "conflict",
		ModelCoverage: ModelCoverage{
			Modeled:    []string{"identity_policy", "resource_policy", "kms_key_policy"},
			NotModeled: []string{"scp", "permissions_boundary", "session_policy", "condition_value_context"},
		},
	}

	allowMatches := []z3.Bool{}
	denyMatches := []z3.Bool{}
	for i := range model.Stmt {
		s := &model.Stmt[i]
		match := s.PrincipalMatch.And(s.ActionMatch, s.ResourceMatch, s.ConditionMatch)
		switch s.Effect {
		case "Allow":
			allowMatches = append(allowMatches, match)
		case "Deny":
			denyMatches = append(denyMatches, match)
		}
	}
	if len(allowMatches) == 0 || len(denyMatches) == 0 {
		r.Result = "unsatisfiable"
		r.Interpretation = "no conflict possible: the model has no Allow/Deny pair"
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	solver := z3.NewSolver(model.Ctx)
	solver.Assert(orOf(model.Ctx, allowMatches))
	solver.Assert(orOf(model.Ctx, denyMatches))

	sat, err := solver.Check()
	r.SolveTimeMs = time.Since(start).Milliseconds()
	if err != nil {
		r.Result = "error"
		r.Interpretation = fmt.Sprintf("z3 check error: %v", err)
		return r
	}
	r.Result = satString(sat)
	if sat {
		r.Interpretation = "policies disagree: there exists a (principal, action, resource) where one Allow matches and one Deny matches"
		if witness := extractTriple(solver, model); witness != nil {
			r.Witness = witness
		}
	} else {
		r.Interpretation = "policies are mutually consistent: no triple is both allowed and denied"
	}
	return r
}

func extractTriple(solver *z3.Solver, model *compiler.CompiledModel) map[string]string {
	m := solver.Model()
	if m == nil {
		return nil
	}

	pVar, aVar, rVar := model.EvalVarsExported()
	out := map[string]string{
		"principal": resolveConstName(model.Principals, m.Eval(pVar, true).String()),
		"action":    resolveConstName(model.Actions, m.Eval(aVar, true).String()),
		"resource":  resolveConstName(model.Resources, m.Eval(rVar, true).String()),
	}
	return out
}

func resolveConstName(universe map[string]z3.Uninterpreted, printed string) string {
	for literal, c := range universe {
		if c.String() == printed {
			return literal
		}
	}
	return printed
}

func orOf(ctx *z3.Context, terms []z3.Bool) z3.Bool {
	if len(terms) == 0 {
		return ctx.FromBool(false)
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return terms[0].Or(terms[1:]...)
}
