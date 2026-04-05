package setup

import "github.com/sufield/stave/internal/core/outcome"

// --- Doctor ---

type DoctorRequest struct {
	Cwd        string `json:"cwd,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Format     string `json:"format,omitempty"`
}

type DoctorResponse struct {
	Checks    []DoctorCheck `json:"checks"`
	AllPassed bool          `json:"all_passed"`
}

type DoctorCheck struct {
	Name    string         `json:"name"`
	Status  outcome.Status `json:"status"`
	Message string         `json:"message,omitempty"`
	Fix     string         `json:"fix,omitempty"`
}
