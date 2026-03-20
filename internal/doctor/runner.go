package doctor

import "slices"

// Registry maintains an ordered collection of diagnostic check functions.
type Registry struct {
	checks []CheckFunc
}

// NewRegistry creates a new Registry from the provided check functions.
func NewRegistry(checks ...CheckFunc) *Registry {
	return &Registry{
		checks: slices.Clone(checks),
	}
}

// Run executes all checks in the registry against the provided context.
// It returns the list of results and a boolean indicating success (true if no FAIL status).
func (r *Registry) Run(ctx *Context) ([]Check, bool) {
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

		if res.Status == StatusFail {
			success = false
		}

		results = append(results, res)
	}

	return results, success
}
