package doctor

import (
	"context"

	"github.com/sufield/stave/internal/core/domain"
	intdoctor "github.com/sufield/stave/internal/doctor"
)

// CheckRunner satisfies usecases.DoctorCheckRunnerPort.
type CheckRunner struct{}

// RunChecks executes the standard doctor checks and converts results to domain types.
func (r *CheckRunner) RunChecks(_ context.Context, cwd, binaryPath string) ([]domain.DoctorCheck, bool, error) {
	dctx := intdoctor.NewContext()
	dctx.Cwd = cwd
	dctx.BinaryPath = binaryPath

	checks, allPassed := intdoctor.Run(dctx)

	out := make([]domain.DoctorCheck, len(checks))
	for i, c := range checks {
		out[i] = domain.DoctorCheck{
			Name:    c.Name,
			Status:  string(c.Status),
			Message: c.Message,
			Fix:     c.Fix,
		}
	}
	return out, allPassed, nil
}
