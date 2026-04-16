package effort

import (
	"testing"
)

func TestHoursFor_Override(t *testing.T) {
	m := &Model{
		DefaultHours: 4,
		Overrides:    map[string]float64{"CTL.A.001": 1},
	}
	if m.HoursFor("CTL.A.001") != 1 {
		t.Errorf("override: got %f, want 1", m.HoursFor("CTL.A.001"))
	}
}

func TestHoursFor_Default(t *testing.T) {
	m := &Model{DefaultHours: 4}
	if m.HoursFor("CTL.UNKNOWN.001") != 4 {
		t.Errorf("default: got %f, want 4", m.HoursFor("CTL.UNKNOWN.001"))
	}
}

func TestHoursFor_NilModel(t *testing.T) {
	var m *Model
	if m.HoursFor("CTL.A.001") != 4 {
		t.Errorf("nil model: got %f, want 4", m.HoursFor("CTL.A.001"))
	}
}

func TestPlanSprint_WithinBudget(t *testing.T) {
	items := []SprintItem{
		{ControlID: "A", RiskScore: 800, EffortHours: 1, ROIScore: 800},
		{ControlID: "B", RiskScore: 400, EffortHours: 2, ROIScore: 200},
		{ControlID: "C", RiskScore: 300, EffortHours: 40, ROIScore: 7.5},
	}
	inSprint, excluded := PlanSprint(items, 20)
	if len(inSprint) != 2 {
		t.Errorf("in sprint = %d, want 2", len(inSprint))
	}
	if len(excluded) != 1 {
		t.Errorf("excluded = %d, want 1", len(excluded))
	}
	if excluded[0].ControlID != "C" {
		t.Errorf("excluded should be C (too large), got %s", excluded[0].ControlID)
	}
}

func TestPlanSprint_EmptyBudget(t *testing.T) {
	items := []SprintItem{
		{ControlID: "A", EffortHours: 1},
	}
	inSprint, excluded := PlanSprint(items, 0)
	if len(inSprint) != 0 {
		t.Error("zero budget should include nothing")
	}
	if len(excluded) != 1 {
		t.Error("all items should be excluded")
	}
}
