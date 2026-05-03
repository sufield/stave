package queries

import (
	"fmt"
	"time"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/experiments/z3-solver/compiler"
)

// QueryCompatibility answers "Can principal X perform action Y on
// resource Z given all currently-modeled policies?". The result is
// SAT when the IAM evaluator says ALLOW for the (P, A, R) triple,
// UNSAT when every modeled layer denies (or no Allow matches).
//
// The query constrains the model's shared (P, A, R) symbolic
// variables to the literal values supplied by the caller, then
// asserts EvaluateAccess and asks Z3 for satisfiability. The
// returned result includes the unmodeled-layer audit so a UNSAT
// verdict reads as "no modeled layer permits" rather than
// "guaranteed denial in production".
func QueryCompatibility(model *compiler.CompiledModel, principal, action, resource string) *QueryResult {
	start := time.Now()

	r := &QueryResult{
		QueryName: "compatibility",
		ModelCoverage: ModelCoverage{
			Modeled:    []string{"identity_policy", "resource_policy", "kms_key_policy", "trust_policy"},
			NotModeled: []string{"scp", "permissions_boundary", "session_policy", "vpc_endpoint_policy"},
		},
	}

	pConst, ok := model.Principals[principal]
	if !ok {
		r.Result = "unmodeled"
		r.Interpretation = fmt.Sprintf("principal %q not present in the snapshot's policy universe", principal)
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}
	aConst, ok := model.Actions[action]
	if !ok {
		r.Result = "unmodeled"
		r.Interpretation = fmt.Sprintf("action %q not present in the snapshot's action universe", action)
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}
	rConst, ok := model.Resources[resource]
	if !ok {
		r.Result = "unmodeled"
		r.Interpretation = fmt.Sprintf("resource %q not present in the snapshot's resource universe", resource)
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	pVar, aVar, rVar := model.EvalVarsExported()
	solver := z3.NewSolver(model.Ctx)
	solver.Assert(pVar.Eq(pConst))
	solver.Assert(aVar.Eq(aConst))
	solver.Assert(rVar.Eq(rConst))
	solver.Assert(model.EvaluateAccess())

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
			"%s is permitted to perform %s on %s under the modeled layers",
			principal, action, resource)
		r.Witness = map[string]string{
			"principal": principal,
			"action":    action,
			"resource":  resource,
		}
	} else {
		r.Interpretation = fmt.Sprintf(
			"no modeled layer grants %s the action %s on %s",
			principal, action, resource)
	}
	return r
}
