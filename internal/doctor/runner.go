package doctor

import "github.com/samber/lo"

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
	ctx.FillDefaults()
	results := lo.FilterMap(checks, func(fn CheckFunc, _ int) (Check, bool) {
		c := fn(ctx)
		return c, c.Name != ""
	})
	hasFail := lo.SomeBy(results, func(c Check) bool { return c.Status == StatusFail })
	return results, hasFail
}
