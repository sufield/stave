package prereq

import (
	validation "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/doctor"
)

// DoctorPrereqChecks runs system health checks and transforms them into domain-level
// prerequisite checks.
func DoctorPrereqChecks(cwd, binaryPath string) []validation.ValidationFinding {
	doctorChecks, _ := doctor.Run(&doctor.SystemEnvironment{
		Cwd:        cwd,
		BinaryPath: binaryPath,
	})

	out := make([]validation.ValidationFinding, 0, len(doctorChecks))
	for _, c := range doctorChecks {
		out = append(out, validation.ValidationFinding{
			Name:        c.Name,
			Status:      c.Status, // same type — no mapping needed
			Message:     c.Message,
			Remediation: c.Remediation,
		})
	}
	return out
}
