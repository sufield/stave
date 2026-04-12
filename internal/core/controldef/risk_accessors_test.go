package controldef

import (
	"testing"
)

func TestBaseImpact(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		d := ControlDefinition{Params: NewParams(map[string]any{"base_impact": float64(10)})}
		if got := d.BaseImpact(); got != 10 {
			t.Errorf("BaseImpact() = %d, want 10", got)
		}
	})
	t.Run("missing defaults to 0", func(t *testing.T) {
		d := ControlDefinition{Params: NewParams(nil)}
		if got := d.BaseImpact(); got != 0 {
			t.Errorf("BaseImpact() = %d, want 0", got)
		}
	})
	t.Run("zero params", func(t *testing.T) {
		d := ControlDefinition{}
		if got := d.BaseImpact(); got != 0 {
			t.Errorf("BaseImpact() = %d, want 0", got)
		}
	})
}

func TestAttackStage(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		d := ControlDefinition{Params: NewParams(map[string]any{"attack_stage": "initial_access"})}
		if got := d.AttackStage(); got != "initial_access" {
			t.Errorf("AttackStage() = %q, want initial_access", got)
		}
	})
	t.Run("missing defaults to empty", func(t *testing.T) {
		d := ControlDefinition{}
		if got := d.AttackStage(); got != "" {
			t.Errorf("AttackStage() = %q, want empty", got)
		}
	})
}

func TestChainIDs(t *testing.T) {
	t.Run("present as []any", func(t *testing.T) {
		d := ControlDefinition{Params: NewParams(map[string]any{
			"chain_ids": []any{"public_phi_exposure", "storage_safety"},
		})}
		ids := d.ChainIDs()
		if len(ids) != 2 || ids[0] != "public_phi_exposure" {
			t.Errorf("ChainIDs() = %v, want [public_phi_exposure storage_safety]", ids)
		}
	})
	t.Run("present as []string", func(t *testing.T) {
		d := ControlDefinition{Params: NewParams(map[string]any{
			"chain_ids": []string{"chain1"},
		})}
		ids := d.ChainIDs()
		if len(ids) != 1 || ids[0] != "chain1" {
			t.Errorf("ChainIDs() = %v, want [chain1]", ids)
		}
	})
	t.Run("missing defaults to nil", func(t *testing.T) {
		d := ControlDefinition{}
		if got := d.ChainIDs(); got != nil {
			t.Errorf("ChainIDs() = %v, want nil", got)
		}
	})
}

func TestBlastRadius(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		d := ControlDefinition{Params: NewParams(map[string]any{
			"blast_radius": map[string]any{
				"type":       "detection",
				"multiplier": float64(2.5),
			},
		})}
		if got := d.BlastRadiusType(); got != "detection" {
			t.Errorf("BlastRadiusType() = %q, want detection", got)
		}
		if got := d.BlastMultiplier(); got != 2.5 {
			t.Errorf("BlastMultiplier() = %f, want 2.5", got)
		}
	})
	t.Run("missing defaults", func(t *testing.T) {
		d := ControlDefinition{}
		if got := d.BlastRadiusType(); got != "" {
			t.Errorf("BlastRadiusType() = %q, want empty", got)
		}
		if got := d.BlastMultiplier(); got != 1.0 {
			t.Errorf("BlastMultiplier() = %f, want 1.0", got)
		}
	})
	t.Run("multiplier defaults to 1.0 when zero", func(t *testing.T) {
		d := ControlDefinition{Params: NewParams(map[string]any{
			"blast_radius": map[string]any{"type": "prevention"},
		})}
		if got := d.BlastMultiplier(); got != 1.0 {
			t.Errorf("BlastMultiplier() = %f, want 1.0", got)
		}
	})
}
