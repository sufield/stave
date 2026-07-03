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
		Property:    predicate.NewFieldPath("properties.tls.min_version"),
		ActualValue: "TLSv1.0",
		Operator:    predicate.OpEq,
		UnsafeValue: "TLSv1.0",
	}}

	changes := DeriveChanges(misconfigs)

	if len(changes) != 1 {
		t.Fatalf("len = %d, want 1", len(changes))
	}
	c := changes[0]
	if c.HasSafeDefault {
		t.Error("expected HasSafeDefault = false for non-boolean OpEq")
	}
	// Non-boolean OpEq does not have a unique safe value, but it does
	// have a meaningful constraint: the property must not equal the
	// unsafe value. Surface the constraint instead of leaving
	// RequiredValue blank.
	wantRequired := "any value other than TLSv1.0"
	if c.RequiredValue != wantRequired {
		t.Errorf("RequiredValue = %q, want %q", c.RequiredValue, wantRequired)
	}
	if c.Description == "" || c.Description == "Change properties.tls.min_version from TLSv1.0" {
		t.Errorf("Description = %q, want it to mention moving away from TLSv1.0", c.Description)
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
