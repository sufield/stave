// Package sprintplanner provides capacity-constrained sprint planning
// using a greedy knapsack algorithm sorted by ROI.
package sprintplanner

import (
	"sort"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// SprintItem is a finding scored for sprint inclusion.
type SprintItem struct {
	ControlID   string  `json:"control_id"`
	AssetID     string  `json:"asset_id"`
	Severity    string  `json:"severity"`
	EffortHours float64 `json:"effort_hours"`
	RiskScore   float64 `json:"risk_score"`
	ROI         float64 `json:"roi"`
}

// SprintResult holds the greedy knapsack output.
type SprintResult struct {
	Items         []SprintItem `json:"items"`
	TotalHours    float64      `json:"total_hours"`
	Capacity      float64      `json:"capacity"`
	RiskReduction float64      `json:"risk_reduction"`
	LeftOut       []SprintItem `json:"left_out"`
}

// Input configures the sprint planning run.
type Input struct {
	Findings      []remediation.Finding
	CapacityHours float64
	DefaultHours  float64
	ControlHours  map[string]float64 // per-control effort override
}

// Plan selects the highest-ROI findings that fit within the capacity budget.
// Findings are scored by risk_reduction / effort_hours, sorted descending,
// and greedily selected until the budget is exhausted.
func Plan(input Input) SprintResult {
	defaultH := input.DefaultHours
	if defaultH <= 0 {
		defaultH = 4
	}

	items := make([]SprintItem, 0, len(input.Findings))
	for i := range input.Findings {
		f := &input.Findings[i]

		hours := defaultH
		if h, ok := input.ControlHours[string(f.ControlID)]; ok {
			hours = h
		}

		risk := f.Evidence.UnsafeDurationHours
		if risk <= 0 {
			risk = 1
		}

		roi := 0.0
		if hours > 0 {
			roi = risk / hours
		}

		items = append(items, SprintItem{
			ControlID:   string(f.ControlID),
			AssetID:     string(f.AssetID),
			Severity:    f.ControlSeverity.String(),
			EffortHours: hours,
			RiskScore:   risk,
			ROI:         roi,
		})
	}

	// Sort by ROI descending for greedy selection.
	sort.Slice(items, func(i, j int) bool {
		return items[i].ROI > items[j].ROI
	})

	result := SprintResult{
		Capacity: input.CapacityHours,
	}
	remaining := input.CapacityHours

	for _, item := range items {
		if item.EffortHours <= remaining {
			result.Items = append(result.Items, item)
			result.TotalHours += item.EffortHours
			result.RiskReduction += item.RiskScore
			remaining -= item.EffortHours
		} else {
			result.LeftOut = append(result.LeftOut, item)
		}
	}

	return result
}
