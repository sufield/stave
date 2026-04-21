package controldef

import (
	"testing"

	"github.com/sufield/stave/internal/core/predicate"
)

func TestDeriveDefect_SimpleBoolean(t *testing.T) {
	p := &UnsafePredicate{
		All: []PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.compute.kind"),
				Op:    predicate.OpEq,
				Value: NewOperand("instance"),
			},
			{
				Field: predicate.NewFieldPath("properties.compute.encryption.ebs_encrypted"),
				Op:    predicate.OpEq,
				Value: NewOperand(false),
			},
		},
	}
	got := DeriveDefect(p)
	t.Logf("Derived: %q", got)
	if got == "" {
		t.Error("expected non-empty derived defect")
	}
}

func TestDeriveDefect_UnlabeledPath(t *testing.T) {
	p := &UnsafePredicate{
		All: []PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.totally.unknown.path"),
				Op:    predicate.OpEq,
				Value: NewOperand(true),
			},
		},
	}
	got := DeriveDefect(p)
	t.Logf("Derived: %q", got)
	// Algorithmic label should produce something for "unknown path"
}
