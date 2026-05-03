package schemaval

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/outcome"
)

// ValidationFinding describes a structural issue or logical error in the
// input controls or resource snapshots that prevents a safe evaluation.
type ValidationFinding struct {
	Name        string         `json:"name"`
	Status      outcome.Status `json:"status"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation,omitempty"`
	FixCommand  string         `json:"fix_command,omitempty"`
}

// IsPassing reports whether the finding's status is outcome.Pass.
// Centralised so readiness callers stop comparing the raw enum
// at every site.
func (v *ValidationFinding) IsPassing() bool {
	return v != nil && v.Status == outcome.Pass
}

// IsWarning reports whether the finding is recorded at the Warn
// status level. Sibling of IsPassing — the readiness aggregator
// uses the predicate to bin findings without re-reading the raw
// enum.
func (v *ValidationFinding) IsWarning() bool {
	return v != nil && v.Status == outcome.Warn
}

// AssessmentSummary aggregates metrics from the structural validation of the
// security controls and configuration states.
type AssessmentSummary struct {
	Errors            int `json:"errors"`
	Warnings          int `json:"warnings"`
	ControlsVerified  int `json:"controls_verified"`
	StatesVerified    int `json:"states_verified"`
	ResourcesAnalyzed int `json:"resources_analyzed"`
}

// ReadinessAssessment captures the result of a pre-evaluation integrity check.
// It determines if the environment and control-set are in a safe state to proceed.
type ReadinessAssessment struct {
	IsSafe            bool              `json:"is_safe"`
	ControlSource     string            `json:"control_source"`
	ObservationSource string            `json:"observation_source"`
	Summary           AssessmentSummary `json:"summary"`
	findings          []ValidationFinding
}

// NewReadinessAssessment initializes an assessment, defaulting to a safe state.
func NewReadinessAssessment(controlSrc, observationSrc string) *ReadinessAssessment {
	return &ReadinessAssessment{
		IsSafe:            true,
		ControlSource:     controlSrc,
		ObservationSource: observationSrc,
		findings:          make([]ValidationFinding, 0),
	}
}

// IsReady reports whether the readiness check considers the
// environment safe to proceed with `stave apply`. Wraps the
// IsSafe field so cmd-side callers stop reading the field
// directly.
func (r *ReadinessAssessment) IsReady() bool {
	return r != nil && r.IsSafe
}

// NextCommand returns the recommended next CLI command for the
// operator to run, based on readiness state. When the assessment
// is ready, the next command is `stave apply`; when unsafe, the
// command is `stave validate` so the operator can investigate
// the recorded findings before re-running.
//
// Centralised here so the cmd-side renderer stops constructing
// the string from (IsSafe, ControlSource, ObservationSource)
// inline.
func (r *ReadinessAssessment) NextCommand() string {
	if r == nil {
		return ""
	}
	verb := "validate"
	if r.IsReady() {
		verb = "apply"
	}
	return fmt.Sprintf("stave %s --controls %s --observations %s",
		verb, r.ControlSource, r.ObservationSource)
}

// Findings returns a copy of the recorded structural or environmental issues.
func (r *ReadinessAssessment) Findings() []ValidationFinding {
	out := make([]ValidationFinding, len(r.findings))
	copy(out, r.findings)
	return out
}

// RecordFinding logs a validation issue and updates the aggregate safety state.
func (r *ReadinessAssessment) RecordFinding(f ValidationFinding) {
	switch {
	case !f.IsPassing() && !f.IsWarning():
		// Anything that's neither passing nor a warning is a hard
		// failure: it knocks the readiness flag off and counts
		// against the error budget.
		r.IsSafe = false
		r.Summary.Errors++
	case f.IsWarning():
		r.Summary.Warnings++
	}
	r.findings = append(r.findings, f)
}

// EvaluationState contains the diagnostics and load metrics from an active evaluation.
type EvaluationState struct {
	Diagnostics *diag.Assessment
	LoadMetrics struct {
		ControlsLoaded  int
		SnapshotsLoaded int
		ResourcesLoaded int
	}
}

// AssessmentContext provides the parameters required to evaluate configuration safety.
type AssessmentContext struct {
	ControlSource          string
	ObservationSource      string
	SLAThreshold           time.Duration
	CurrentTime            time.Time
	ControlFlagsSet        bool
	HasEnabledControlPacks bool
	PreflightChecks        []ValidationFinding
	RunEvaluation          func(sla time.Duration, now time.Time) (EvaluationState, error)
}
