// Package compliancepath computes the minimum-effort remediation path
// to reach a target compliance readiness percentage. Uses a greedy
// set cover approximation: at each step, pick the fix that satisfies
// the most unsatisfied framework requirements.
package compliancepath

import (
	"errors"
	"slices"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// ErrUnknownFramework is returned by Compute when TotalControls is zero
// (typically because the requested compliance framework has no
// controls in the catalog). Callers should surface this as a
// configuration error rather than the previous silent fallback to
// 100% readiness.
var ErrUnknownFramework = errors.New("compliancepath: total controls is zero — unknown or empty framework")

// SprintBundle groups findings that share a remediation action.
type SprintBundle struct {
	Action            string   `json:"action"`
	ControlIDs        []string `json:"control_ids"`
	EffortHours       float64  `json:"effort_hours,omitempty"`
	ReadinessGain     float64  `json:"readiness_gain_pct"`
	FrameworksBenefit []string `json:"frameworks_benefit"`
}

// PathResult holds the compliance path output.
type PathResult struct {
	TargetFramework  string         `json:"target_framework"`
	TargetReadiness  float64        `json:"target_readiness_pct"`
	CurrentReadiness float64        `json:"current_readiness_pct"`
	Gap              float64        `json:"gap_pct"`
	Bundles          []SprintBundle `json:"sprint_bundles"`
	ProjectedScore   float64        `json:"projected_readiness_pct"`
	TotalEffort      float64        `json:"total_effort_hours"`
}

// EffortModel maps control IDs to estimated remediation hours.
type EffortModel struct {
	DefaultHours float64            `yaml:"default_hours" json:"default_hours"`
	Controls     map[string]float64 `yaml:"controls" json:"controls"`
}

// Input configures the compliance path computation.
type Input struct {
	Findings        []remediation.Finding
	TargetFramework string
	TargetReadiness float64
	TotalControls   int // total controls in the target framework
	Effort          *EffortModel
}

// Compute produces the minimum viable compliance path using greedy
// set cover. Each iteration picks the remediation action that covers
// the most remaining violations.
//
// Returns ErrUnknownFramework when in.TotalControls is zero. The
// previous behavior — silently returning CurrentReadiness=100 — was a
// dangerous false-safe: a typo'd framework name produced a "fully
// compliant" report.
func Compute(in Input) (*PathResult, error) {
	if in.TotalControls <= 0 {
		return nil, ErrUnknownFramework
	}

	// Group findings by remediation action.
	actionGroups := make(map[string][]remediation.Finding)
	for i := range in.Findings {
		f := &in.Findings[i]
		action := f.RemediationSpec.Action
		if action == "" {
			action = string(f.ControlID) + " remediation"
		}
		actionGroups[action] = append(actionGroups[action], *f)
	}

	violatingControls := countUniqueControls(in.Findings)
	currentReadiness := (1.0 - float64(violatingControls)/float64(in.TotalControls)) * 100
	remaining := make(map[string]bool, len(in.Findings))
	for i := range in.Findings {
		remaining[string(in.Findings[i].ControlID)] = true
	}

	var bundles []SprintBundle
	totalEffort := 0.0
	projected := currentReadiness

	for projected < in.TargetReadiness && len(remaining) > 0 {
		// Greedy: pick the action that resolves the most remaining controls.
		bestAction := ""
		bestCount := 0
		for action, findings := range actionGroups {
			count := 0
			for fi := range findings {
				if remaining[string(findings[fi].ControlID)] {
					count++
				}
			}
			if count > bestCount {
				bestCount = count
				bestAction = action
			}
		}

		if bestAction == "" || bestCount == 0 {
			break
		}

		// Build the bundle.
		findings := actionGroups[bestAction]
		var controlIDs []string
		var frameworks []string
		fwSet := make(map[string]bool)
		for fi := range findings {
			f := &findings[fi]
			if remaining[string(f.ControlID)] {
				controlIDs = append(controlIDs, string(f.ControlID))
				delete(remaining, string(f.ControlID))
				for fw := range f.ControlCompliance {
					fwStr := string(fw)
					if !fwSet[fwStr] {
						fwSet[fwStr] = true
						frameworks = append(frameworks, fwStr)
					}
				}
			}
		}

		readinessGain := float64(len(controlIDs)) / float64(in.TotalControls) * 100
		effort := effortForControls(controlIDs, in.Effort)

		slices.Sort(controlIDs)
		slices.Sort(frameworks)

		bundles = append(bundles, SprintBundle{
			Action:            bestAction,
			ControlIDs:        controlIDs,
			EffortHours:       effort,
			ReadinessGain:     readinessGain,
			FrameworksBenefit: frameworks,
		})

		projected += readinessGain
		totalEffort += effort
		delete(actionGroups, bestAction)
	}

	return &PathResult{
		TargetFramework:  in.TargetFramework,
		TargetReadiness:  in.TargetReadiness,
		CurrentReadiness: currentReadiness,
		Gap:              in.TargetReadiness - currentReadiness,
		Bundles:          bundles,
		ProjectedScore:   projected,
		TotalEffort:      totalEffort,
	}, nil
}

func countUniqueControls(findings []remediation.Finding) int {
	seen := make(map[string]bool, len(findings))
	for i := range findings {
		seen[string(findings[i].ControlID)] = true
	}
	return len(seen)
}

func effortForControls(controlIDs []string, model *EffortModel) float64 {
	if model == nil {
		return 0
	}
	total := 0.0
	for _, id := range controlIDs {
		if h, ok := model.Controls[id]; ok {
			total += h
		} else {
			total += model.DefaultHours
		}
	}
	return total
}
