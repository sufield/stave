// Package teamgate provides per-team CI/CD gating logic. Filters
// assessment findings to a specific team and evaluates threshold
// policies so that one team's violations do not block another
// team's deployment.
package teamgate

import (
	"github.com/sufield/stave/internal/app/teams"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	corereport "github.com/sufield/stave/internal/core/report"
)

// Threshold encapsulates a finding count limit rule.
// Negative values (e.g. -1) represent a disabled check.
type Threshold int

const (
	DisabledThreshold      Threshold = -1
	ZeroToleranceThreshold Threshold = 0
)

// NewThreshold constructs a Threshold value object.
func NewThreshold(limit int) Threshold {
	return Threshold(limit)
}

// IsDisabled reports whether threshold check is disabled (-1).
func (t Threshold) IsDisabled() bool {
	return t < 0
}

// IsExceeded reports whether finding count exceeds this threshold.
func (t Threshold) IsExceeded(count int) bool {
	return !t.IsDisabled() && count > int(t)
}

// Value returns the raw integer threshold limit.
func (t Threshold) Value() int {
	return int(t)
}

// Thresholds defines the maximum allowed findings per severity.
//
// A value of -1 disables the check for that severity. The zero value
// means "no tolerance" (any finding at that severity fails the gate).
// Callers wanting CLI-typical behavior — block on critical/high,
// inform on medium — should construct via DefaultThresholds().
type Thresholds struct {
	MaxCritical Threshold `json:"max_critical"`
	MaxHigh     Threshold `json:"max_high"`
	MaxMedium   Threshold `json:"max_medium"`
}

// DefaultThresholds returns the recommended CLI defaults: zero
// tolerance for critical and high findings, medium not checked.
// Production gates typically want this shape — medium-severity
// noise during evaluation shouldn't block a deploy that has no
// high or critical findings.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MaxCritical: ZeroToleranceThreshold,
		MaxHigh:     ZeroToleranceThreshold,
		MaxMedium:   DisabledThreshold,
	}
}

// GateReason classifies the outcome rationale for a team gate evaluation.
type GateReason string

const (
	ReasonCriticalThresholdExceeded GateReason = "critical findings exceed threshold"
	ReasonHighThresholdExceeded     GateReason = "high findings exceed threshold"
	ReasonMediumThresholdExceeded   GateReason = "medium findings exceed threshold"
)

// GateResult holds the per-team gate evaluation.
type GateResult struct {
	TeamID        teams.TeamID `json:"team_id"`
	Passed        bool         `json:"passed"`
	CriticalCount int          `json:"critical_count"`
	HighCount     int          `json:"high_count"`
	MediumCount   int          `json:"medium_count"`
	TotalFindings int          `json:"total_findings"`
	Reason        GateReason   `json:"reason,omitempty"`
}

// FindingList is a domain collection of remediation.Finding items with query methods.
type FindingList []remediation.Finding

// Len returns the count of findings in the collection.
func (fl FindingList) Len() int {
	return len(fl)
}

// BySeverity returns a new FindingList collection filtered by policy severity.
func (fl FindingList) BySeverity(sev policy.Severity) FindingList {
	if len(fl) == 0 {
		return nil
	}
	var filtered FindingList
	for i := range fl {
		if fl[i].ControlSeverity == sev {
			filtered = append(filtered, fl[i])
		}
	}
	return filtered
}

// Input configures the gate evaluation.
type Input struct {
	Findings   FindingList
	Manifest   *teams.Manifest
	TeamID     teams.TeamID
	Thresholds Thresholds
}

// Evaluate filters findings to the specified team and checks thresholds.
func Evaluate(in Input) GateResult {
	var teamFindings []remediation.Finding
	for i := range in.Findings {
		f := &in.Findings[i]
		teamID := teams.TeamID(f.OwnerTeamID)
		if in.Manifest != nil {
			owner := in.Manifest.ResolveOwner(nil, string(f.AssetID), f.ControlID)
			teamID = owner.TeamID
		}
		if teamID == in.TeamID {
			teamFindings = append(teamFindings, *f)
		}
	}

	var counts corereport.SeverityCounts
	for i := range teamFindings {
		counts.Add(teamFindings[i].ControlSeverity)
	}

	result := GateResult{
		TeamID:        in.TeamID,
		CriticalCount: counts.Critical,
		HighCount:     counts.High,
		MediumCount:   counts.Medium,
		TotalFindings: len(teamFindings),
		Passed:        true,
	}

	// Apply thresholds via Threshold domain methods.
	if in.Thresholds.MaxCritical.IsExceeded(counts.Critical) {
		result.Passed = false
		result.Reason = ReasonCriticalThresholdExceeded
	} else if in.Thresholds.MaxHigh.IsExceeded(counts.High) {
		result.Passed = false
		result.Reason = ReasonHighThresholdExceeded
	} else if in.Thresholds.MaxMedium.IsExceeded(counts.Medium) {
		result.Passed = false
		result.Reason = ReasonMediumThresholdExceeded
	}

	return result
}
