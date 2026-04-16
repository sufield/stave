// Package effort provides effort estimation for remediation ROI ranking.
package effort

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Model holds effort estimates per control.
type Model struct {
	DefaultHours float64            `yaml:"default_hours" json:"default_hours"`
	Overrides    map[string]float64 `yaml:"overrides"     json:"overrides"`
}

// LoadFromFile reads an effort model YAML.
func LoadFromFile(path string) (*Model, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user path
	if err != nil {
		return nil, fmt.Errorf("read effort model: %w", err)
	}
	var m Model
	if unmarshalErr := yaml.Unmarshal(data, &m); unmarshalErr != nil {
		return nil, fmt.Errorf("parse effort model: %w", unmarshalErr)
	}
	if m.DefaultHours <= 0 {
		m.DefaultHours = 4
	}
	return &m, nil
}

// HoursFor returns the effort estimate for a control.
func (m *Model) HoursFor(controlID string) float64 {
	if m == nil {
		return 4 // global default
	}
	if h, ok := m.Overrides[controlID]; ok {
		return h
	}
	return m.DefaultHours
}

// SprintItem is a finding with ROI score for sprint planning.
type SprintItem struct {
	ControlID   string  `json:"control_id"`
	RiskScore   float64 `json:"risk_score"`
	EffortHours float64 `json:"effort_hours"`
	ROIScore    float64 `json:"roi_score"`
	InSprint    bool    `json:"in_sprint"`
}

// PlanSprint selects highest-ROI items within a budget.
func PlanSprint(items []SprintItem, budgetHours float64) (inSprint []SprintItem, excluded []SprintItem) {
	remaining := budgetHours
	for i := range items {
		if items[i].EffortHours <= remaining {
			items[i].InSprint = true
			inSprint = append(inSprint, items[i])
			remaining -= items[i].EffortHours
		} else {
			excluded = append(excluded, items[i])
		}
	}
	return inSprint, excluded
}
