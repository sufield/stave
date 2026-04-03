package doctor

import (
	"context"

	"github.com/sufield/stave/internal/core/setup"
	intdoctor "github.com/sufield/stave/internal/doctor"
)

// CheckRunner satisfies setup.DoctorCheckRunnerPort.
type CheckRunner struct{}

// RunChecks executes the standard doctor checks and converts results to setup types.
func (r *CheckRunner) RunChecks(_ context.Context, req setup.DoctorRequest) (setup.DoctorResponse, error) {
	dctx := intdoctor.NewContext()
	dctx.Cwd = req.Cwd
	dctx.BinaryPath = req.BinaryPath

	checks, allPassed := intdoctor.Run(dctx)

	out := make([]setup.DoctorCheck, len(checks))
	for i, c := range checks {
		out[i] = setup.DoctorCheck{
			Name:    c.Name,
			Status:  c.Status.String(),
			Message: c.Message,
			Fix:     c.Fix,
		}
	}
	return setup.DoctorResponse{Checks: out, AllPassed: allPassed}, nil
}
