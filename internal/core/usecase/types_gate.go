package usecase

import "time"

// --- Gate ---

type GateRequest struct {
	Policy            string        `json:"policy"`
	EvaluationPath    string        `json:"evaluation_path,omitempty"`
	BaselinePath      string        `json:"baseline_path,omitempty"`
	ControlsDir       string        `json:"controls_dir,omitempty"`
	ObservationsDir   string        `json:"observations_dir,omitempty"`
	MaxUnsafeDuration time.Duration `json:"max_unsafe_duration,omitempty"`
	Now               *time.Time    `json:"now,omitempty"`
}

type GateResponse struct {
	Policy            string    `json:"policy"`
	Passed            bool      `json:"pass"`
	Reason            string    `json:"reason"`
	CheckedAt         time.Time `json:"checked_at"`
	EvaluationPath    string    `json:"evaluation_path,omitempty"`
	BaselinePath      string    `json:"baseline_path,omitempty"`
	ControlsPath      string    `json:"controls_path,omitempty"`
	ObservationsPath  string    `json:"observations_path,omitempty"`
	CurrentViolations int       `json:"current_violations,omitempty"`
	NewViolations     int       `json:"new_violations,omitempty"`
	OverdueUpcoming   int       `json:"overdue_upcoming,omitempty"`
}
