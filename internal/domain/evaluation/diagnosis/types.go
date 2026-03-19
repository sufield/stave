package diagnosis

import (
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
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

// Sanitized returns a copy with asset identifiers replaced by deterministic tokens.
func (d Issue) Sanitized(r kernel.IDSanitizer) Issue {
	if d.AssetID == "" {
		return d
	}
	raw := string(d.AssetID)
	token := r.ID(raw)
	d.AssetID = asset.ID(token)
	d.Evidence = strings.ReplaceAll(d.Evidence, raw, token)
	return d
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

// Sanitized returns a deep copy with asset identifiers replaced by
// deterministic tokens.
func (dr *Report) Sanitized(r kernel.IDSanitizer) *Report {
	if dr == nil {
		return nil
	}
	out := *dr
	out.Issues = make([]Issue, len(dr.Issues))
	for i, d := range dr.Issues {
		out.Issues[i] = d.Sanitized(r)
	}
	return &out
}

// Input encapsulates all data required to run a diagnosis.
type Input struct {
	Snapshots       asset.Snapshots
	Controls        []policy.ControlDefinition
	Findings        []evaluation.Finding
	Result          *evaluation.Result
	MaxUnsafe       time.Duration
	Now             time.Time
	PredicateParser policy.PredicateParser
	PredicateEval   policy.PredicateEval

	// cached summary computed at creation
	summary Summary
}

// NewInput initializes the input and pre-computes summary statistics.
func NewInput(
	snapshots asset.Snapshots,
	controls []policy.ControlDefinition,
	findings []evaluation.Finding,
	result *evaluation.Result,
	maxUnsafe time.Duration,
	now time.Time,
	parser policy.PredicateParser,
	eval policy.PredicateEval,
) Input {
	i := Input{
		Snapshots:       snapshots,
		Controls:        controls,
		Findings:        findings,
		Result:          result,
		MaxUnsafe:       maxUnsafe,
		Now:             now,
		PredicateParser: parser,
		PredicateEval:   eval,
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
		MaxUnsafeThreshold: kernel.Duration(i.MaxUnsafe),
		EvaluationTime:     i.Now,
	}

	if len(i.Snapshots) == 0 {
		return s
	}

	s.MinCapturedAt, s.MaxCapturedAt = i.calculateTemporalBounds()
	s.TimeSpan = kernel.Duration(s.MaxCapturedAt.Sub(s.MinCapturedAt))
	s.TotalAssets = i.countUniqueAssets()

	if i.Result != nil {
		s.ViolationsFound = len(i.Result.Findings)
		s.AttackSurface = i.Result.Summary.AttackSurface
	}

	return s
}

func (i *Input) calculateTemporalBounds() (minT, maxT time.Time) {
	if len(i.Snapshots) == 0 {
		return
	}

	minT = i.Snapshots[0].CapturedAt
	maxT = i.Snapshots[0].CapturedAt

	for _, snap := range i.Snapshots {
		if snap.CapturedAt.Before(minT) {
			minT = snap.CapturedAt
		}
		if snap.CapturedAt.After(maxT) {
			maxT = snap.CapturedAt
		}
	}
	return
}

func (i *Input) countUniqueAssets() int {
	if len(i.Snapshots) == 0 {
		return 0
	}

	capacity := len(i.Snapshots[0].Assets)
	unique := make(map[asset.ID]struct{}, capacity)

	for _, snap := range i.Snapshots {
		for _, a := range snap.Assets {
			unique[a.ID] = struct{}{}
		}
	}
	return len(unique)
}
