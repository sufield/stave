package diagnosis

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Scenario represents the category of the diagnostic result.
type Scenario string

const (
	ScenarioExpectedNone      Scenario = "expected_violations_none"
	ScenarioViolationEvidence Scenario = "violation_evidence"
	ScenarioEmptyFindings     Scenario = "empty_findings"
)

// Issue represents a single diagnostic finding.
type Issue struct {
	Case     Scenario `json:"case"`
	Signal   string   `json:"signal"`
	Evidence string   `json:"evidence"`
	Action   string   `json:"action"`
	Command  string   `json:"command,omitempty"`
	AssetID  asset.ID `json:"asset_id,omitempty"`
}

// Summary contains aggregate metrics about the diagnostic input.
type Summary struct {
	TotalSnapshots     int             `json:"total_snapshots"`
	TotalAssets        int             `json:"total_assets"`
	TotalControls      int             `json:"total_controls"`
	TimeSpan           kernel.Duration `json:"time_span"`
	MinCapturedAt      time.Time       `json:"min_captured_at"`
	MaxCapturedAt      time.Time       `json:"max_captured_at"`
	EvaluationTime     time.Time       `json:"evaluation_time"`
	MaxUnsafeThreshold kernel.Duration `json:"max_unsafe_threshold"`
	ViolationsFound    int             `json:"violations_found"`
	AttackSurface      int             `json:"attack_surface"`
}

// Report is the top-level container for a diagnostic run.
type Report struct {
	Issues  []Issue `json:"diagnostics"`
	Summary Summary `json:"summary"`
}

// DiagnosticFinding is a lightweight view of an evaluation finding,
// carrying only the fields the diagnosis package needs. This avoids
// importing the evaluation package.
type DiagnosticFinding struct {
	AssetID             asset.ID         `json:"asset_id"`
	ControlID           kernel.ControlID `json:"control_id"`
	FirstUnsafeAt       time.Time        `json:"first_unsafe_at"`
	LastSeenUnsafeAt    time.Time        `json:"last_seen_unsafe_at"`
	UnsafeDurationHours float64          `json:"unsafe_duration_hours"`
	ThresholdHours      float64          `json:"threshold_hours"`
}

// Input encapsulates all data required to run a diagnosis.
type Input struct {
	Snapshots         asset.Snapshots
	Controls          []policy.ControlDefinition
	Findings          []DiagnosticFinding
	ViolationsFound   int
	AttackSurface     int
	MaxUnsafeDuration time.Duration
	Now               time.Time
	PredicateEval     policy.PredicateEval

	// cached summary computed at creation
	summary Summary
}

// NewInput initializes the input and pre-computes summary statistics.
func NewInput(
	snapshots asset.Snapshots,
	controls []policy.ControlDefinition,
	findings []DiagnosticFinding,
	violationsFound int,
	attackSurface int,
	maxUnsafe time.Duration,
	now time.Time,
	eval policy.PredicateEval,
) Input {
	i := Input{
		Snapshots:         snapshots,
		Controls:          controls,
		Findings:          findings,
		ViolationsFound:   violationsFound,
		AttackSurface:     attackSurface,
		MaxUnsafeDuration: maxUnsafe,
		Now:               now,
		PredicateEval:     eval,
	}
	i.summary = i.buildSummary()
	return i
}

// Summarize returns pre-computed metadata about the input data.
func (i *Input) Summarize() Summary {
	if i == nil {
		return Summary{}
	}
	return i.summary
}

func (i *Input) buildSummary() Summary {
	s := Summary{
		TotalSnapshots:     len(i.Snapshots),
		TotalControls:      len(i.Controls),
		MaxUnsafeThreshold: kernel.Duration(i.MaxUnsafeDuration),
		EvaluationTime:     i.Now,
	}

	if len(i.Snapshots) == 0 {
		return s
	}

	s.MinCapturedAt, s.MaxCapturedAt = i.Snapshots.TemporalBounds()
	s.TimeSpan = kernel.Duration(s.MaxCapturedAt.Sub(s.MinCapturedAt))
	s.TotalAssets = i.Snapshots.UniqueAssetCount()

	s.ViolationsFound = i.ViolationsFound
	s.AttackSurface = i.AttackSurface

	return s
}
