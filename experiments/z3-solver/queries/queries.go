// Package queries hosts the high-level questions the Z3 experiment
// answers against a CompiledModel. Each query is a function that
// pushes its query-specific assertions onto a fresh solver, runs
// Check, and returns a [QueryResult] carrying the SAT/UNSAT verdict
// plus enough structured context to render a proof certificate.
package queries

// QueryResult is the wire-shape every query produces. Fields are
// JSON-tagged so the CLI can render the certificate directly to
// stdout or to a file. Result is the SMT verdict; Interpretation
// is the human-readable meaning ("attack path exists" / "no
// reachable path"); Witness / UnsatCore carry the structured
// evidence depending on the verdict.
type QueryResult struct {
	QueryName      string            `json:"query_name"`
	Result         string            `json:"result"`
	Interpretation string            `json:"interpretation"`
	Witness        map[string]string `json:"witness,omitempty"`
	UnsatCore      []string          `json:"unsat_core,omitempty"`
	SolveTimeMs    int64             `json:"solve_time_ms"`
	ModelCoverage  ModelCoverage     `json:"model_coverage"`
}

// ModelCoverage names the policy / graph / invariant features the
// query reasons over so consumers do not over-trust a result. The
// honest accounting matters: a "no attack path" verdict from a
// model that omits VPC endpoint policies is sound only relative
// to what the model includes.
type ModelCoverage struct {
	Modeled    []string `json:"modeled"`
	NotModeled []string `json:"not_modeled"`
}

// satString collapses a (sat, err) pair from go-z3's Solver.Check
// into the wire-format string. err propagates back to the caller
// via the QueryResult's Interpretation field — the experiment's
// queries do not surface raw Z3 errors as their result.
func satString(sat bool) string {
	if sat {
		return "satisfiable"
	}
	return "unsatisfiable"
}
