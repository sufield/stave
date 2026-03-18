package validation

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/diag"
)

// Status represents the result of a prerequisite check.
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

// Label returns the uppercase display form of the status (e.g. "PASS", "WARN", "FAIL").
func (s Status) Label() string {
	return strings.ToUpper(string(s))
}

type PrereqCheck struct {
	Name    string
	Status  Status
	Message string
	Fix     string
}

type Issue struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
	Command string `json:"command,omitempty"`
}

type Summary struct {
	Errors                   int `json:"errors"`
	Warnings                 int `json:"warnings"`
	ControlsChecked          int `json:"controls_checked"`
	SnapshotsChecked         int `json:"snapshots_checked"`
	AssetObservationsChecked int `json:"asset_observations_checked"`
}

type ReadinessReport struct {
	Ready           bool    `json:"ready"`
	ControlsDir     string  `json:"controls_dir"`
	ObservationsDir string  `json:"observations_dir"`
	NextCommand     string  `json:"next_command"`
	Summary         Summary `json:"summary"`
	issues          []Issue
}

// NewReadinessReport returns an initialized ReadinessReport.
func NewReadinessReport(controlsDir, observationsDir string) *ReadinessReport {
	return &ReadinessReport{
		Ready:           true,
		ControlsDir:     controlsDir,
		ObservationsDir: observationsDir,
	}
}

// Issues returns the recorded issues. Use RecordIssue to append.
func (r *ReadinessReport) Issues() []Issue { return r.issues }

// Finalize sets NextCommand based on the report's ready state.
func (r *ReadinessReport) Finalize() {
	if r.Ready {
		r.NextCommand = fmt.Sprintf("stave apply --controls %s --observations %s", r.ControlsDir, r.ObservationsDir)
	} else {
		r.NextCommand = "stave plan"
	}
}

// RecordIssue appends an issue and updates Ready and Summary counters.
func (r *ReadinessReport) RecordIssue(issue Issue) {
	switch issue.Status {
	case StatusFail:
		r.Ready = false
		r.Summary.Errors++
	case StatusWarn:
		r.Summary.Warnings++
	}
	r.issues = append(r.issues, issue)
}

type ValidationResult struct {
	Diagnostics *diag.Result
	Summary     struct {
		ControlsLoaded          int
		SnapshotsLoaded         int
		AssetObservationsLoaded int
	}
}

type ReadinessInput struct {
	ControlsDir           string
	ObservationsDir       string
	MaxUnsafe             time.Duration
	Now                   time.Time
	ControlsFlagSet       bool
	HasEnabledControlPack bool
	PrereqChecks          []PrereqCheck
	Validate              func(maxUnsafe time.Duration, now time.Time) (ValidationResult, error)
}
