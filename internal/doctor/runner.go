package doctor

import (
	"slices"

	"github.com/sufield/stave/internal/core/outcome"
)

// CheckSuite maintains an ordered collection of diagnostic check functions.
type CheckSuite struct {
	checks []CheckFunc
}

// NewCheckSuite creates a new CheckSuite from the provided check functions.
func NewCheckSuite(checks ...CheckFunc) *CheckSuite {
	return &CheckSuite{
		checks: slices.Clone(checks),
	}
}

// Run executes all checks in the registry against the provided context.
// It returns the list of results and a boolean indicating success (true if no FAIL status).
func (r *CheckSuite) Run(ctx *Context) ([]Check, bool) {
	if r == nil || len(r.checks) == 0 {
		return nil, true
	}

	if ctx == nil {
		ctx = NewContext()
	}
	ctx.FillDefaults()

	results := make([]Check, 0, len(r.checks))
	success := true

	for _, checkFn := range r.checks {
		res := checkFn(ctx)

		if res.Name == "" {
			continue
		}

		if res.Status == outcome.Fail {
			success = false
		}

		results = append(results, res)
	}

	return results, success
}
