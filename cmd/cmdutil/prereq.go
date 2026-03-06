package cmdutil

import (
	"os"

	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/domain/validation"
)

// DoctorPrereqChecks runs doctor checks and maps them to readiness prereq checks.
func DoctorPrereqChecks() []validation.PrereqCheck {
	cwd, _ := os.Getwd()
	binaryPath, _ := os.Executable()
	doctorChecks, _ := doctor.Run(doctor.Context{
		Cwd:        cwd,
		BinaryPath: binaryPath,
	})
	out := make([]validation.PrereqCheck, 0, len(doctorChecks))
	for _, c := range doctorChecks {
		status := validation.PrereqPass
		switch c.Status {
		case doctor.StatusFail:
			status = validation.PrereqFail
		case doctor.StatusWarn:
			status = validation.PrereqWarn
		}
		out = append(out, validation.PrereqCheck{
			Name:    c.Name,
			Status:  status,
			Message: c.Message,
			Fix:     c.Fix,
		})
	}
	return out
}
