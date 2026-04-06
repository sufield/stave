package doctor

import (
	"fmt"

	"github.com/sufield/stave/internal/core/outcome"
)

// Diagnostic represents the outcome of a system readiness or environment health check.
type Diagnostic struct {
	Name        string         `json:"name"`
	Status      outcome.Status `json:"status"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation,omitempty"`
}

// IsFailure reports whether the diagnostic detected a critical environment issue.
func (d Diagnostic) IsFailure() bool {
	return d.Status == outcome.Fail
}

// String implements fmt.Stringer for structured logging of system health.
func (d Diagnostic) String() string {
	return fmt.Sprintf("[%s] %s: %s", d.Status, d.Name, d.Message)
}

// SystemEnvironment encapsulates the host and runtime data required for preflight checks.
type SystemEnvironment struct {
	Cwd          string
	BinaryPath   string
	OS           string
	Arch         string
	Runtime      string
	BuildVersion string

	// Providers (injectable for testing)
	PathLookupFn func(file string) (string, error)
	EnvVarFn     func(key string) string
}

// Probe is the signature for an individual environment health check.
type Probe func(env *SystemEnvironment) Diagnostic
