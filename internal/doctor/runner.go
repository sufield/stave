package doctor

// Registry defines a set of diagnostic checks that can be executed together.
type Registry struct {
	checks []CheckFunc
}

func NewRegistry(checks ...CheckFunc) Registry {
	cloned := make([]CheckFunc, len(checks))
	copy(cloned, checks)
	return Registry{checks: cloned}
}

func (r Registry) Run(ctx Context) ([]Check, bool) {
	return runChecks(ctx, r.checks)
}

func RunWithRegistry(ctx Context, registry Registry) ([]Check, bool) {
	return registry.Run(ctx)
}

func runChecks(ctx Context, checks []CheckFunc) ([]Check, bool) {
	ctx = withDefaults(ctx)
	results := make([]Check, 0, len(checks))
	hasFail := false
	for _, fn := range checks {
		c := fn(ctx)
		if c.Name == "" {
			continue
		}
		if c.Status == StatusFail {
			hasFail = true
		}
		results = append(results, c)
	}
	return results, hasFail
}
