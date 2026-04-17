package sarifbaseline

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func bf(ctl string, ast string, sev policy.Severity) BaselineFinding {
	return BaselineFinding{
		ControlID: kernel.ControlID(ctl),
		AssetID:   asset.ID(ast),
		Severity:  sev,
	}
}

func TestCompare_NewFinding(t *testing.T) {
	current := []BaselineFinding{bf("CTL.A.001", "asset1", policy.SeverityHigh)}
	baseline := []BaselineFinding{bf("CTL.B.001", "asset2", policy.SeverityHigh)}

	result := Compare(current, baseline)

	state := result.Lookup("CTL.A.001", "asset1")
	if state != StateNew {
		t.Errorf("state = %s, want new", state)
	}
}

func TestCompare_UnchangedFinding(t *testing.T) {
	current := []BaselineFinding{bf("CTL.A.001", "asset1", policy.SeverityHigh)}
	baseline := []BaselineFinding{bf("CTL.A.001", "asset1", policy.SeverityHigh)}

	result := Compare(current, baseline)

	state := result.Lookup("CTL.A.001", "asset1")
	if state != StateUnchanged {
		t.Errorf("state = %s, want unchanged", state)
	}
}

func TestCompare_AbsentFinding(t *testing.T) {
	current := []BaselineFinding{}
	baseline := []BaselineFinding{bf("CTL.A.001", "asset1", policy.SeverityHigh)}

	result := Compare(current, baseline)

	state := result.Lookup("CTL.A.001", "asset1")
	if state != StateAbsent {
		t.Errorf("state = %s, want absent", state)
	}
}

func TestCompare_NoBaseline_AllNew(t *testing.T) {
	current := []BaselineFinding{
		bf("CTL.A.001", "asset1", policy.SeverityHigh),
		bf("CTL.B.001", "asset2", policy.SeverityMedium),
	}

	result := Compare(current, nil)

	for _, f := range current {
		state := result.Lookup(f.ControlID, f.AssetID)
		if state != StateNew {
			t.Errorf("%s state = %s, want new", f.ControlID, state)
		}
	}
}

func TestBuildSuppression_PopulatesFields(t *testing.T) {
	s := BuildSuppression("alice@co.com", "Migration in progress", "2026-07-01", "exempt-123")

	if s.Kind != "inSource" {
		t.Errorf("kind = %s, want inSource", s.Kind)
	}
	if s.Status != "accepted" {
		t.Errorf("status = %s, want accepted", s.Status)
	}
	if s.Justification != "Migration in progress" {
		t.Errorf("justification = %s", s.Justification)
	}
	if s.Properties["approver"] != "alice@co.com" {
		t.Errorf("approver = %v", s.Properties["approver"])
	}
}
