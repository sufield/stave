package prereq

import (
	validation "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/doctor"
)

// DoctorPrereqChecks runs system health checks and transforms them into domain-level
// prerequisite checks. It requires explicit paths to ensure testability and
// environment awareness.
func DoctorPrereqChecks(cwd, binaryPath string) []validation.Issue {
	doctorChecks, _ := doctor.Run(&doctor.Context{
		Cwd:        cwd,
		BinaryPath: binaryPath,
	})

	out := make([]validation.Issue, 0, len(doctorChecks))
	for _, c := range doctorChecks {
		out = append(out, validation.Issue{
			Name:    c.Name,
			Status:  mapDoctorStatus(c.Status),
			Message: c.Message,
			Fix:     c.Fix,
		})
	}
	return out
}

// mapDoctorStatus performs a clean translation between the system-health layer
// and the domain-validation layer.
func mapDoctorStatus(s doctor.Status) validation.Status {
	switch s {
	case doctor.StatusFail:
		return validation.StatusFail
	case doctor.StatusWarn:
		return validation.StatusWarn
	case doctor.StatusPass:
		return validation.StatusPass
	default:
		return validation.StatusFail
	}
}
