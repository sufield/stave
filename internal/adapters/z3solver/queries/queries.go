//go:build cgo && z3

package queries

// QueryResult is the wire shape every query produces.
type QueryResult struct {
	QueryName      string            `json:"query_name"`
	Result         string            `json:"result"`
	Interpretation string            `json:"interpretation"`
	Witness        map[string]string `json:"witness,omitempty"`
	UnsatCore      []string          `json:"unsat_core,omitempty"`
	SolveTimeMs    int64             `json:"solve_time_ms"`
	ModelCoverage  ModelCoverage     `json:"model_coverage"`
}

// ModelCoverage names what the query reasons over.
type ModelCoverage struct {
	Modeled    []string `json:"modeled"`
	NotModeled []string `json:"not_modeled"`
}

func satString(sat bool) string {
	if sat {
		return "satisfiable"
	}
	return "unsatisfiable"
}
