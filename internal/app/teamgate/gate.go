// Package teamgate provides per-team CI/CD gating logic. Filters
// assessment findings to a specific team and evaluates threshold
// policies so that one team's violations do not block another
// team's deployment.
package teamgate

import (
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	corereport "github.com/sufield/stave/internal/core/report"
)

// Thresholds defines the maximum allowed findings per severity.
//
// A value of -1 disables the check for that severity. The zero value
// means "no tolerance" (any finding at that severity fails the gate).
// Callers wanting CLI-typical behavior — block on critical/high,
// inform on medium — should construct via DefaultThresholds().
type Thresholds struct {
	MaxCritical int
	MaxHigh     int
	MaxMedium   int
}

// DefaultThresholds returns the recommended CLI defaults: zero
// tolerance for critical and high findings, medium not checked.
// Production gates typically want this shape — medium-severity
// noise during evaluation shouldn't block a deploy that has no
// high or critical findings.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MaxCritical: 0,
		MaxHigh:     0,
		MaxMedium:   -1,
	}
}

// GateResult holds the per-team gate evaluation.
type GateResult struct {
	TeamID        string `json:"team_id"`
	Passed        bool   `json:"passed"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	MediumCount   int    `json:"medium_count"`
	TotalFindings int    `json:"total_findings"`
	Reason        string `json:"reason,omitempty"`
}

// Input configures the gate evaluation.
type Input struct {
	Findings   []remediation.Finding
	Manifest   *teams.Manifest
	TeamID     string
	Thresholds Thresholds
}

// Evaluate filters findings to the specified team and checks thresholds.
func Evaluate(in Input) GateResult {
	var teamFindings []remediation.Finding
	for i := range in.Findings {
		f := &in.Findings[i]
		teamID := string(f.OwnerTeamID)
		if in.Manifest != nil {
			owner := in.Manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
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

	// A negative threshold (-1) disables the check for that severity,
	// matching the documented sentinel. Apply consistently across
	// critical/high/medium so callers don't need a different pattern
	// per tier.
	if in.Thresholds.MaxCritical >= 0 && counts.Critical > in.Thresholds.MaxCritical {
		result.Passed = false
		result.Reason = "critical findings exceed threshold"
	} else if in.Thresholds.MaxHigh >= 0 && counts.High > in.Thresholds.MaxHigh {
		result.Passed = false
		result.Reason = "high findings exceed threshold"
	} else if in.Thresholds.MaxMedium >= 0 && counts.Medium > in.Thresholds.MaxMedium {
		result.Passed = false
		result.Reason = "medium findings exceed threshold"
	}

	return result
}
