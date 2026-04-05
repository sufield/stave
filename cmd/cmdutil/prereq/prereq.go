package prereq

import (
	validation "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/doctor"
)

// DoctorPrereqChecks runs system health checks and transforms them into domain-level
// prerequisite checks.
func DoctorPrereqChecks(cwd, binaryPath string) []validation.Check {
	doctorChecks, _ := doctor.Run(&doctor.Context{
		Cwd:        cwd,
		BinaryPath: binaryPath,
	})

	out := make([]validation.Check, 0, len(doctorChecks))
	for _, c := range doctorChecks {
		out = append(out, validation.Check{
			Name:    c.Name,
			Status:  c.Status, // same type — no mapping needed
			Message: c.Message,
			Fix:     c.Fix,
		})
	}
	return out
}
