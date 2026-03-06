package validation

import (
	"time"

	"github.com/sufield/stave/internal/domain/diag"
)

// PrereqStatus represents the result of a prerequisite check.
type PrereqStatus string

const (
	PrereqPass PrereqStatus = "pass"
	PrereqWarn PrereqStatus = "warn"
	PrereqFail PrereqStatus = "fail"
)

type PrereqCheck struct {
	Name    string
	Status  PrereqStatus
	Message string
	Fix     string
}

type ReadinessIssue struct {
	Name    string       `json:"name"`
	Status  PrereqStatus `json:"status"`
	Message string       `json:"message"`
	Fix     string       `json:"fix,omitempty"`
	Command string       `json:"command,omitempty"`
}

type ReadinessSummary struct {
	Errors                   int `json:"errors"`
	Warnings                 int `json:"warnings"`
	ControlsChecked          int `json:"controls_checked"`
	SnapshotsChecked         int `json:"snapshots_checked"`
	AssetObservationsChecked int `json:"asset_observations_checked"`
}

type ReadinessReport struct {
	Ready           bool             `json:"ready"`
	ControlsDir     string           `json:"controls_dir"`
	ObservationsDir string           `json:"observations_dir"`
	NextCommand     string           `json:"next_command"`
	Summary         ReadinessSummary `json:"summary"`
	issues          []ReadinessIssue
}

// Issues returns the recorded issues. Use RecordIssue to append.
func (r *ReadinessReport) Issues() []ReadinessIssue { return r.issues }

// Finalize sets NextCommand based on the report's ready state.
func (r *ReadinessReport) Finalize() {
	if r.Ready {
		r.NextCommand = "stave apply --controls " + r.ControlsDir + " --observations " + r.ObservationsDir
	} else {
		r.NextCommand = "stave plan"
	}
}

// RecordIssue appends an issue and updates Ready and Summary counters.
func (r *ReadinessReport) RecordIssue(issue ReadinessIssue) {
	switch issue.Status {
	case PrereqFail:
		r.Ready = false
		r.Summary.Errors++
	case PrereqWarn:
		r.Summary.Warnings++
	}
	r.issues = append(r.issues, issue)
}

type ReadinessValidationSummary struct {
	ControlsLoaded          int
	SnapshotsLoaded         int
	AssetObservationsLoaded int
}

type ReadinessValidationResult struct {
	Diagnostics *diag.Result
	Summary     ReadinessValidationSummary
}

type ReadinessInput struct {
	ControlsDir           string
	ObservationsDir       string
	MaxUnsafe             string
	Now                   string
	ControlsFlagSet       bool
	HasEnabledControlPack bool
	PrereqChecks          []PrereqCheck
	Validate              func(maxUnsafe time.Duration, now time.Time) (ReadinessValidationResult, error)
}
