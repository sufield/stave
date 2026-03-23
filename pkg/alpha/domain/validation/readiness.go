package validation

import (
	"strings"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/diag"
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

// PrereqCheck represents a single prerequisite validation with its status and remediation guidance.
type PrereqCheck struct {
	Name    string
	Status  Status
	Message string
	Fix     string
}

// Issue describes a validation issue with severity and suggested fix.
type Issue struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
	Command string `json:"command,omitempty"`
}

// Summary aggregates the counts of checks, errors, and warnings from a readiness assessment.
type Summary struct {
	Errors                   int `json:"errors"`
	Warnings                 int `json:"warnings"`
	ControlsChecked          int `json:"controls_checked"`
	SnapshotsChecked         int `json:"snapshots_checked"`
	AssetObservationsChecked int `json:"asset_observations_checked"`
}

// ReadinessReport holds the result of a readiness assessment including prerequisites and issues.
// NextCommand is not set here — CLI command names are a presentation concern owned by the cmd layer.
type ReadinessReport struct {
	Ready           bool    `json:"ready"`
	ControlsDir     string  `json:"controls_dir"`
	ObservationsDir string  `json:"observations_dir"`
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

// Finalize marks the report as complete. NextCommand should be set by
// the caller based on the Ready state — the domain layer does not know
// about CLI command names.
func (r *ReadinessReport) Finalize() {}

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

// Result contains diagnostics and summary counts from a validation run.
type Result struct {
	Diagnostics *diag.Result
	Summary     struct {
		ControlsLoaded          int
		SnapshotsLoaded         int
		AssetObservationsLoaded int
	}
}

// ReadinessInput provides the parameters needed to perform a readiness assessment.
type ReadinessInput struct {
	ControlsDir            string
	ObservationsDir        string
	MaxUnsafeDuration      time.Duration
	Now                    time.Time
	ControlsFlagSet        bool
	HasEnabledControlPacks bool
	PrereqChecks           []PrereqCheck
	Validate               func(maxUnsafeDuration time.Duration, now time.Time) (Result, error)
}
