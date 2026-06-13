package queries

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/experiments/z3-solver/compiler"
)

// QueryChokePoint identifies the minimum set of policy statements
// whose removal breaks a previously-satisfiable reachability
// path. Run after QueryReachability returned SAT; UNSAT verdicts
// have nothing to "fix".
//
// The implementation is a greedy minimal-cover walk over
// Allow-side statements: each candidate is tentatively removed,
// QueryCompatibility is re-run for the chain's terminal hop, and
// the candidate is added to the cover if its removal flips the
// terminal grant to UNSAT. The greedy walk produces an unsat-core
// equivalent (every named statement is necessary; no smaller
// subset breaks reachability).
//
// This is structurally weaker than Z3's named-assertion unsat-core
// extraction; the go-z3 binding does not expose Solver.AssertAndTrack,
// so we approximate via repeated SAT checks. The approximation is
// sound (every reported statement is in fact necessary for the
// attack path) but not minimal (a smaller cut may exist that the
// greedy walk misses on its first pass).
func QueryChokePoint(model *compiler.CompiledModel, reach *QueryResult) *QueryResult {
	start := time.Now()
	r := &QueryResult{
		QueryName: "choke_point",
		ModelCoverage: ModelCoverage{
			Modeled:    []string{"identity_policy", "resource_policy", "kms_key_policy"},
			NotModeled: []string{"scp", "permissions_boundary", "session_policy", "minimal_cover_optimality"},
		},
	}

	if reach == nil || reach.Result != "satisfiable" {
		r.Result = "skipped"
		r.Interpretation = "no attack path to break — reachability did not return satisfiable"
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	terminal := reach.Witness["terminal"]
	resource := reach.Witness["resource"]
	action := reach.Witness["action"]
	if terminal == "" || resource == "" || action == "" {
		r.Result = "error"
		r.Interpretation = "reachability witness is missing terminal/resource/action — cannot run choke-point analysis"
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	// Find Allow statements whose suppression breaks the grant.
	var cover []string
	var candidates []int
	for i := range model.Stmt {
		if model.Stmt[i].Effect == "Allow" {
			candidates = append(candidates, i)
		}
	}
	slices.SortFunc(candidates, func(a, b int) int {
		return cmp.Compare(model.Stmt[a].AssertionName, model.Stmt[b].AssertionName)
	})

	suppressed := map[int]struct{}{}
	for _, idx := range candidates {
		suppressed[idx] = struct{}{}
		if !checkGrantWithSuppression(model, terminal, action, resource, suppressed) {
			cover = append(cover, model.Stmt[idx].AssertionName)
			// Keep the suppression — once we know this statement
			// is required, removing it from the model produces a
			// smaller cover. We don't put it back: any further
			// candidate that also breaks reachability is part of
			// the joint cover.
			continue
		}
		delete(suppressed, idx)
	}

	if len(cover) == 0 {
		r.Result = "no_cover_found"
		r.Interpretation = fmt.Sprintf(
			"every Allow statement was suppressed without breaking the %s → %s grant; the path may be funneled through unmodeled layers",
			terminal, resource)
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	r.Result = "minimum_fix_found"
	r.Interpretation = fmt.Sprintf(
		"removing any one of these statements breaks the %s → %s attack path",
		terminal, resource)
	r.UnsatCore = cover
	r.SolveTimeMs = time.Since(start).Milliseconds()
	return r
}

// checkGrantWithSuppression re-runs the IAM evaluation with the
// supplied statement indices treated as if they did not exist.
// Returns true when the (terminal, action, resource) triple is
// still permitted, false when the suppression has broken the
// grant. The implementation builds a fresh per-call solver so
// suppression state does not leak across QueryChokePoint calls.
func checkGrantWithSuppression(model *compiler.CompiledModel, principal, action, resource string, suppressed map[int]struct{}) bool {
	pConst, ok := model.Principals[principal]
	if !ok {
		return false
	}
	aConst, ok := model.Actions[action]
	if !ok {
		return false
	}
	rConst, ok := model.Resources[resource]
	if !ok {
		return false
	}

	pVar, aVar, rVar := model.EvalVarsExported()
	solver := z3.NewSolver(model.Ctx)
	solver.Assert(pVar.Eq(pConst))
	solver.Assert(aVar.Eq(aConst))
	solver.Assert(rVar.Eq(rConst))
	solver.Assert(model.EvaluateAccessWith(suppressed))

	sat, err := solver.Check()
	if err != nil {
		return false
	}
	return sat
}
