package controldef

import (
	"strings"
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

func TestDeriveDefect_PolicyAbsent(t *testing.T) {
	p := &UnsafePredicate{
		All: []PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.storage.kind"),
				Op:    predicate.OpEq,
				Value: NewOperand("bucket"),
			},
			{
				Field: predicate.NewFieldPath("properties.storage.policy_json"),
				Op:    predicate.OpEq,
				Value: NewOperand(""),
			},
		},
	}
	got := DeriveDefect(p)
	want := "Bucket has no explicit policy (relying on implicit deny)."
	if got != want {
		t.Errorf("policy-absent defect:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestDeriveDefect_PolicyOverlyBroad(t *testing.T) {
	p := &UnsafePredicate{
		All: []PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.storage.kind"),
				Op:    predicate.OpEq,
				Value: NewOperand("bucket"),
			},
			{
				Field: predicate.NewFieldPath("properties.storage.access.policy_is_effectively_public"),
				Op:    predicate.OpEq,
				Value: NewOperand(true),
			},
		},
	}
	got := DeriveDefect(p)
	want := "Bucket policy allows overly broad access (effectively public per AWS PolicyStatus)."
	if got != want {
		t.Errorf("policy-overly-broad defect:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestDeriveDefect_PolicyMissingScoping(t *testing.T) {
	p := &UnsafePredicate{
		All: []PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.storage.kind"),
				Op:    predicate.OpEq,
				Value: NewOperand("bucket"),
			},
			{
				Field: predicate.NewFieldPath("properties.storage.access.policy_has_scoping_condition"),
				Op:    predicate.OpPresent,
				Value: NewOperand(true),
			},
			{
				Field: predicate.NewFieldPath("properties.storage.access.policy_has_scoping_condition"),
				Op:    predicate.OpEq,
				Value: NewOperand(false),
			},
		},
	}
	got := DeriveDefect(p)
	want := "Bucket policy contains a non-narrow Allow without a scoping Condition."
	// The Present rule emits "Policy scoping condition is present" before
	// the eq rule's special-case clause; assert the trailing sentence is
	// the actionable one rather than the generic "is present" lead-in.
	if got == "" || !strings.HasSuffix(got, want) {
		t.Errorf("policy-missing-scoping defect:\n  got:  %q\n  want suffix: %q", got, want)
	}
}
