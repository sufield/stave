// Package teamgate provides per-team CI/CD gating logic. Filters
// assessment findings to a specific team and evaluates threshold
// policies so that one team's violations do not block another
// team's deployment.
package teamgate

import (
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// Thresholds defines the maximum allowed findings per severity.
type Thresholds struct {
	MaxCritical int
	MaxHigh     int
	MaxMedium   int
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
		owner := in.Manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		if owner.TeamID == in.TeamID {
			teamFindings = append(teamFindings, *f)
		}
	}

	var critical, high, medium int
	for i := range teamFindings {
		switch teamFindings[i].ControlSeverity.String() {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		}
	}

	result := GateResult{
		TeamID:        in.TeamID,
		CriticalCount: critical,
		HighCount:     high,
		MediumCount:   medium,
		TotalFindings: len(teamFindings),
		Passed:        true,
	}

	if critical > in.Thresholds.MaxCritical {
		result.Passed = false
		result.Reason = "critical findings exceed threshold"
	} else if high > in.Thresholds.MaxHigh {
		result.Passed = false
		result.Reason = "high findings exceed threshold"
	} else if in.Thresholds.MaxMedium >= 0 && medium > in.Thresholds.MaxMedium {
		result.Passed = false
		result.Reason = "medium findings exceed threshold"
	}

	return result
}
