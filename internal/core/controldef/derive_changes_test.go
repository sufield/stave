package controldef

import (
	"testing"

	"github.com/sufield/stave/internal/core/predicate"
)

func TestDeriveChanges_BooleanInversion(t *testing.T) {
	misconfigs := []Misconfiguration{{
		Property:    predicate.NewFieldPath("properties.storage.public_access_block.block_public_acls"),
		ActualValue: false,
		Operator:    predicate.OpEq,
		UnsafeValue: false,
	}}

	changes := DeriveChanges(misconfigs)

	if len(changes) != 1 {
		t.Fatalf("len = %d, want 1", len(changes))
	}
	c := changes[0]
	if c.PropertyPath != "properties.storage.public_access_block.block_public_acls" {
		t.Errorf("PropertyPath = %q", c.PropertyPath)
	}
	if c.CurrentValue != "false" {
		t.Errorf("CurrentValue = %q, want false", c.CurrentValue)
	}
	if c.RequiredValue != "true" {
		t.Errorf("RequiredValue = %q, want true", c.RequiredValue)
	}
	if !c.HasSafeDefault {
		t.Error("expected HasSafeDefault = true for boolean inversion")
	}
}

func TestDeriveChanges_ContextDependent(t *testing.T) {
	misconfigs := []Misconfiguration{{
		Property:    predicate.NewFieldPath("properties.storage.encryption.kms_key_id"),
		ActualValue: "",
		Operator:    predicate.OpEq,
		UnsafeValue: "",
	}}

	changes := DeriveChanges(misconfigs)

	if len(changes) != 1 {
		t.Fatalf("len = %d, want 1", len(changes))
	}
	c := changes[0]
	if c.HasSafeDefault {
		t.Error("expected HasSafeDefault = false for non-boolean")
	}
	if c.RequiredValue != "" {
		t.Errorf("RequiredValue = %q, want empty", c.RequiredValue)
	}
}

func TestDeriveChanges_MissingField(t *testing.T) {
	misconfigs := []Misconfiguration{{
		Property:    predicate.NewFieldPath("properties.storage.tags.team"),
		ActualValue: nil,
		Operator:    predicate.OpMissing,
	}}

	changes := DeriveChanges(misconfigs)

	if len(changes) != 1 {
		t.Fatalf("len = %d, want 1", len(changes))
	}
	if changes[0].RequiredValue != "present" {
		t.Errorf("RequiredValue = %q, want present", changes[0].RequiredValue)
	}
}

func TestDeriveChanges_EmptyInput(t *testing.T) {
	changes := DeriveChanges(nil)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for nil input, got %d", len(changes))
	}
}

func TestConfidenceFloat(t *testing.T) {
	tests := []struct {
		level string
		want  float64
	}{
		{"HIGH", 1.0},
		{"MEDIUM", 0.7},
		{"LOW", 0.4},
		{"INCONCLUSIVE", 0.5},
		{"", 0.5},
	}
	for _, tt := range tests {
		if got := ConfidenceFloat(tt.level); got != tt.want {
			t.Errorf("ConfidenceFloat(%q) = %f, want %f", tt.level, got, tt.want)
		}
	}
}
