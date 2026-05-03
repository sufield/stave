package queries

import (
	"fmt"
	"time"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/experiments/z3-solver/compiler"
	"github.com/sufield/stave/pkg/stave"
)

// QueryInvariantVerify answers "Does the unsafe condition encoded
// by this control's predicate hold for ALL possible inputs?".
//
// Stave's CEL evaluator runs the predicate against a snapshot's
// concrete values. Z3 runs it against symbolic values: the
// invariant's properties become free uninterpreted constants in
// the env, so satisfiability of the predicate means "there
// exists some configuration where the unsafe condition holds".
//
//   - SAT means the unsafe condition is reachable: the witness
//     names the property values that trigger it. A solver-grade
//     proof of insecurity, generalised across configurations the
//     snapshot did not capture.
//   - UNSAT means the unsafe condition is unreachable: no
//     configuration of the read properties can make the
//     predicate fire. This is the formal-verification verdict
//     for the modeled fragment.
//
// The model coverage entry surfaces what the predicate did NOT
// model: condition operators, free strings without an enumeration
// constraint, and the closed-vs-open universe choice.
func QueryInvariantVerify(model *compiler.CompiledModel, invariantID string) *QueryResult {
	start := time.Now()

	r := &QueryResult{
		QueryName: "invariant_verify",
		ModelCoverage: ModelCoverage{
			Modeled:    []string{"predicate_tree", "eq_ne_in_present_absent_operators"},
			NotModeled: []string{"condition_value_context", "open_universe_string_constraints"},
		},
	}

	inv, ok := model.Invariants[stave.ControlID(invariantID)]
	if !ok {
		r.Result = "unmodeled"
		r.Interpretation = fmt.Sprintf("invariant %q not present in the loaded catalog", invariantID)
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	stringSort := model.Ctx.UninterpretedSort("PropString")
	boolSort := model.Ctx.BoolSort()
	env := &compiler.InvariantEnv{
		Ctx:        model.Ctx,
		StringSort: stringSort,
		BoolSort:   boolSort,
	}
	predicate := inv.Predicate(env)

	solver := z3.NewSolver(model.Ctx)
	solver.Assert(predicate)

	sat, err := solver.Check()
	r.SolveTimeMs = time.Since(start).Milliseconds()
	if err != nil {
		r.Result = "error"
		r.Interpretation = fmt.Sprintf("z3 check error: %v", err)
		return r
	}
	r.Result = satString(sat)
	if sat {
		r.Interpretation = fmt.Sprintf(
			"invariant %s does NOT hold: there exists an input that triggers the unsafe condition",
			invariantID)
		if witness := extractInvariantWitness(solver, env, inv.Properties); len(witness) > 0 {
			r.Witness = witness
		}
	} else {
		r.Interpretation = fmt.Sprintf(
			"invariant %s holds: no modeled input triggers the unsafe condition",
			invariantID)
	}
	return r
}

// extractInvariantWitness reads back the concrete values Z3
// assigned to each property's symbolic variable. The names are
// stable ("prop:<path>") so the witness keys map directly back to
// the predicate's read sites.
func extractInvariantWitness(solver *z3.Solver, env *compiler.InvariantEnv, properties []string) map[string]string {
	model := solver.Model()
	if model == nil {
		return nil
	}
	out := map[string]string{}
	for _, path := range properties {
		if v, ok := env.StringValues[path]; ok {
			out[path] = model.Eval(v, true).String()
			continue
		}
		if b, ok := env.BoolValues[path]; ok {
			out[path] = model.Eval(b, true).String()
		}
	}
	return out
}
