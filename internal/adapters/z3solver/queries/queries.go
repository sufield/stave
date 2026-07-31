//go:build cgo && z3

package queries

import "github.com/aclements/go-z3/z3"

// QueryResult is the wire shape every query produces.
type QueryResult struct {
	QueryName      string            `json:"query_name"`
	Result         string            `json:"result"`
	Interpretation string            `json:"interpretation"`
	Witness        map[string]string `json:"witness,omitempty"`
	UnsatCore      []string          `json:"unsat_core,omitempty"`
	SolveTimeMs    int64             `json:"solve_time_ms"`
	ModelCoverage  ModelCoverage     `json:"model_coverage"`
	CertificateSMT string            `json:"-"`
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

// captureCertificate snapshots the solver's assertions as SMT-LIB text.
func captureCertificate(solver *z3.Solver, sat bool, queryName string) string {
	result := "unsat"
	if sat {
		result = "sat"
	}
	return "; Stave Proof Certificate — query: " + queryName + "\n" +
		"; Expected result: " + result + "\n" +
		"; Verify: z3 <this-file>\n\n" +
		solver.String() + "\n\n(check-sat)\n"
}
