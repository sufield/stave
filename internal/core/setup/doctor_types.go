package setup

import "github.com/sufield/stave/internal/core/outcome"

// --- Doctor ---

// DoctorRequest is the input for the doctor health check.
type DoctorRequest struct {
	Cwd        string `json:"cwd,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Format     string `json:"format,omitempty"`
}

// DoctorResponse is the output of the doctor health check.
type DoctorResponse struct {
	Checks    []DoctorCheck `json:"checks"`
	AllPassed bool          `json:"all_passed"`
}

// DoctorCheck represents a single health check result.
type DoctorCheck struct {
	Name    string         `json:"name"`
	Status  outcome.Status `json:"status"`
	Message string         `json:"message,omitempty"`
	Fix     string         `json:"fix,omitempty"`
}
