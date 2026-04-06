package schemaval

import (
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
	IsSafe          bool              `json:"is_safe"`
	ControlSource   string            `json:"control_source"`
	InventorySource string            `json:"inventory_source"`
	Summary         AssessmentSummary `json:"summary"`
	findings        []ValidationFinding
}

// NewReadinessAssessment initializes an assessment, defaulting to a safe state.
func NewReadinessAssessment(controlSrc, inventorySrc string) *ReadinessAssessment {
	return &ReadinessAssessment{
		IsSafe:          true,
		ControlSource:   controlSrc,
		InventorySource: inventorySrc,
		findings:        make([]ValidationFinding, 0),
	}
}

// Findings returns a copy of the recorded structural or environmental issues.
func (r *ReadinessAssessment) Findings() []ValidationFinding {
	out := make([]ValidationFinding, len(r.findings))
	copy(out, r.findings)
	return out
}

// RecordFinding logs a validation issue and updates the aggregate safety state.
func (r *ReadinessAssessment) RecordFinding(f ValidationFinding) {
	switch f.Status {
	case outcome.Fail:
		r.IsSafe = false
		r.Summary.Errors++
	case outcome.Warn:
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
	InventorySource        string
	SLAThreshold           time.Duration
	CurrentTime            time.Time
	ControlFlagsSet        bool
	HasEnabledControlPacks bool
	PreflightChecks        []ValidationFinding
	RunEvaluation          func(sla time.Duration, now time.Time) (EvaluationState, error)
}
