package diagnosis

import (
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// Kind represents the type of diagnostic scenario.
type Kind string

const (
	ExpectedNone      Kind = "expected_violations_none"
	ViolationEvidence Kind = "violation_evidence"
	EmptyFindings     Kind = "empty_findings"
)

// Entry represents a single diagnostic finding.
type Entry struct {
	Case     Kind     `json:"case"`
	Signal   string   `json:"signal"`
	Evidence string   `json:"evidence"`
	Action   string   `json:"action"`
	Command  string   `json:"command,omitempty"`
	AssetID  asset.ID `json:"asset_id,omitempty"`
}

// Sanitized returns a copy with asset identifiers replaced by deterministic tokens.
func (d Entry) Sanitized(r kernel.IDSanitizer) Entry {
	out := d
	if d.AssetID != "" {
		raw := string(d.AssetID)
		sanitized := r.ID(raw)
		out.AssetID = asset.ID(sanitized)
		out.Evidence = strings.ReplaceAll(d.Evidence, raw, sanitized)
	}
	return out
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

// Report contains all diagnostic findings.
type Report struct {
	Entries []Entry `json:"diagnostics"`
	Summary Summary `json:"summary"`
}

// Sanitized returns a deep copy with asset identifiers replaced by
// deterministic tokens.
func (dr *Report) Sanitized(r kernel.IDSanitizer) *Report {
	if dr == nil {
		return nil
	}
	out := *dr
	out.Entries = make([]Entry, len(dr.Entries))
	for i, d := range dr.Entries {
		out.Entries[i] = d.Sanitized(r)
	}
	return &out
}

// Input holds all inputs needed for diagnosis.
type Input struct {
	Snapshots asset.Snapshots
	Controls  []policy.ControlDefinition
	Findings  []evaluation.Finding
	Result    *evaluation.Result
	MaxUnsafe time.Duration
	Now       time.Time

	summary      Summary
	summaryReady bool
}

// Params is the constructor parameter object for Input.
type Params struct {
	Snapshots asset.Snapshots
	Controls  []policy.ControlDefinition
	Findings  []evaluation.Finding
	Result    *evaluation.Result
	MaxUnsafe time.Duration
	Now       time.Time
}

// NewInput builds an Input with precomputed summary metadata.
// This front-loads computation so subsequent Summarize calls are O(1).
func NewInput(params Params) Input {
	input := Input{
		Snapshots: params.Snapshots,
		Controls:  params.Controls,
		Findings:  params.Findings,
		Result:    params.Result,
		MaxUnsafe: params.MaxUnsafe,
		Now:       params.Now,
	}
	input.summary = input.buildSummary()
	input.summaryReady = true
	return input
}

// Summarize generates a Summary from the input data.
func (i *Input) Summarize() Summary {
	if i == nil {
		return Summary{}
	}

	if i.summaryReady {
		return i.summary
	}

	s := i.buildSummary()
	i.summary = s
	i.summaryReady = true
	return s
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

	// Evaluation result overlay.
	if i.Result != nil {
		s.ViolationsFound = len(i.Result.Findings)
		s.AttackSurface = i.Result.Summary.AttackSurface
	}

	return s
}

func (i *Input) calculateTemporalBounds() (time.Time, time.Time) {
	if i == nil || len(i.Snapshots) == 0 {
		return time.Time{}, time.Time{}
	}

	earliest := i.Snapshots[0].CapturedAt
	latest := i.Snapshots[0].CapturedAt
	for _, snap := range i.Snapshots {
		if snap.CapturedAt.Before(earliest) {
			earliest = snap.CapturedAt
		}
		if snap.CapturedAt.After(latest) {
			latest = snap.CapturedAt
		}
	}

	return earliest, latest
}

func (i *Input) countUniqueAssets() int {
	if i == nil || len(i.Snapshots) == 0 {
		return 0
	}

	// Presize to reduce map growth churn for larger snapshot sets.
	uniqueAssets := make(map[asset.ID]struct{}, len(i.Snapshots))
	for _, snap := range i.Snapshots {
		for _, r := range snap.Assets {
			uniqueAssets[r.ID] = struct{}{}
		}
	}
	return len(uniqueAssets)
}
