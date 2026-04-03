package schemaval

import (
	"time"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/outcome"
)

// Issue describes a validation finding with severity and suggested fix.
// Consolidates the former PrereqCheck and Issue types into a single model.
type Issue struct {
	Name    string         `json:"name"`
	Status  outcome.Status `json:"status"`
	Message string         `json:"message"`
	Fix     string         `json:"fix,omitempty"`
	Command string         `json:"command,omitempty"`
}

// Summary aggregates counts of checks, errors, and warnings.
type Summary struct {
	Errors                   int `json:"errors"`
	Warnings                 int `json:"warnings"`
	ControlsChecked          int `json:"controls_checked"`
	SnapshotsChecked         int `json:"snapshots_checked"`
	AssetObservationsChecked int `json:"asset_observations_checked"`
}

// Report holds the result of a readiness assessment.
// Issues are unexported to force use of RecordIssue, keeping Summary
// and Ready in sync with the data.
type Report struct {
	Ready           bool    `json:"ready"`
	ControlsDir     string  `json:"controls_dir"`
	ObservationsDir string  `json:"observations_dir"`
	Summary         Summary `json:"summary"`
	issues          []Issue
}

// NewReport returns a Report initialized for success.
func NewReport(controlsDir, observationsDir string) *Report {
	return &Report{
		Ready:           true,
		ControlsDir:     controlsDir,
		ObservationsDir: observationsDir,
	}
}

// Issues returns a copy of the recorded issues to prevent external mutation.
func (r *Report) Issues() []Issue {
	out := make([]Issue, len(r.issues))
	copy(out, r.issues)
	return out
}

// RecordIssue appends an issue and updates Ready and Summary counters.
func (r *Report) RecordIssue(issue Issue) {
	switch issue.Status {
	case outcome.Fail:
		r.Ready = false
		r.Summary.Errors++
	case outcome.Warn:
		r.Summary.Warnings++
	}
	r.issues = append(r.issues, issue)
}

// Result contains diagnostics and summary counts from a validation run.
type Result struct {
	Diagnostics *diag.Result
	Summary     struct {
		ControlsLoaded          int
		SnapshotsLoaded         int
		AssetObservationsLoaded int
	}
}

// Input provides the parameters needed to perform a readiness assessment.
type Input struct {
	ControlsDir            string
	ObservationsDir        string
	MaxUnsafeDuration      time.Duration
	Now                    time.Time
	ControlsFlagSet        bool
	HasEnabledControlPacks bool
	PrereqChecks           []Issue
	Validate               func(maxUnsafeDuration time.Duration, now time.Time) (Result, error)
}
