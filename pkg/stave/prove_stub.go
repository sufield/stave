//go:build !(cgo && z3)

package stave

import (
	"context"
	"errors"
)

// ProveConfig configures a prove query.
type ProveConfig struct {
	SnapshotsDir string
	ControlsDir  string
	Query        string
	Principal    string
	Action       string
	Resource     string
	InvariantID  string
}

// ProveResult wraps the Z3 query result for the facade.
type ProveResult struct {
	QueryName      string            `json:"query_name"`
	Result         string            `json:"result"`
	Interpretation string            `json:"interpretation"`
	Witness        map[string]string `json:"witness,omitempty"`
	UnsatCore      []string          `json:"unsat_core,omitempty"`
	SolveTimeMs    int64             `json:"solve_time_ms"`
	ModelCoverage  struct {
		Modeled    []string `json:"modeled"`
		NotModeled []string `json:"not_modeled"`
	} `json:"model_coverage"`
}

// Prove returns an error when the binary is built without Z3.
func Prove(_ context.Context, _ ProveConfig) (*ProveResult, error) {
	return nil, errors.New("prove: Z3 solver not available (rebuild with: go build -tags 'cgo z3')")
}
