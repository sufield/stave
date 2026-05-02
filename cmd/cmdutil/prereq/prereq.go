package prereq

import (
	validation "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/doctor"
)

// DoctorPrereqChecks runs system health checks and transforms them into domain-level
// prerequisite checks.
//
// doctor.Run returns ([]Diagnostic, bool) where the bool is an
// aggregate "all probes passed" flag — NOT an error. The
// per-probe Status field on each Diagnostic carries the same
// information at finer granularity (FAIL / WARN / PASS / SKIP),
// and the caller's downstream pipeline routes off the per-finding
// status, not the aggregate. Treating doctor.Run's bool as an
// error to propagate would conflate "subsystem broke" (it can't
// — Run never returns one) with "individual probe reported FAIL"
// — they would be the same signal here. The blank-identifier
// assignment is deliberate, documented to forestall a re-audit.
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
