package deps

import (
	"errors"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestExtract_DirectFieldAccess(t *testing.T) {
	pred := &policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq},
		},
	}

	paths, err := Extract(pred)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "properties.storage.access.public_read" {
		t.Errorf("paths = %v, want [properties.storage.access.public_read]", paths)
	}
}

func TestExtract_NestedAnyAll(t *testing.T) {
	pred := &policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.encryption.enabled"), Op: predicate.OpEq},
			{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.logging.target"), Op: predicate.OpPresent},
					{Field: predicate.NewFieldPath("properties.logging.enabled"), Op: predicate.OpEq},
				},
			},
		},
	}

	paths, err := Extract(pred)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("paths = %d, want 3", len(paths))
	}
	// Should be sorted
	if paths[0] != "properties.encryption.enabled" {
		t.Errorf("paths[0] = %s", paths[0])
	}
}

func TestExtract_Deduplication(t *testing.T) {
	pred := &policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq},
			{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq},
		},
	}

	paths, err := Extract(pred)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Errorf("paths = %d, want 1 (deduplicated)", len(paths))
	}
}

func TestExtractFromControl_AliasedPredicateErrors(t *testing.T) {
	ctl := &policy.ControlDefinition{
		UnsafePredicateAlias: "some_external_predicate",
	}

	_, err := ExtractFromControl(ctl)
	if !errors.Is(err, ErrAliasedPredicate) {
		t.Errorf("err = %v, want ErrAliasedPredicate", err)
	}
}

func TestExtract_EmptyPredicate(t *testing.T) {
	pred := &policy.UnsafePredicate{}
	paths, err := Extract(pred)
	if err != nil {
		t.Fatal(err)
	}
	if paths != nil {
		t.Errorf("paths = %v, want nil", paths)
	}
}

func TestExtract_RealCatalogPredicate_S3Public(t *testing.T) {
	// Simulates CTL.S3.PUBLIC.001: any of public_read or public_list
	pred := &policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq},
			{Field: predicate.NewFieldPath("properties.storage.access.public_list"), Op: predicate.OpEq},
		},
	}

	paths, err := Extract(pred)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("paths = %d, want 2", len(paths))
	}
}

func TestExtract_RealCatalogPredicate_AllWithNested(t *testing.T) {
	// Simulates a control with all: [field1, any: [field2, field3]]
	pred := &policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.identity.mfa_enabled"), Op: predicate.OpEq},
			{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.identity.has_hardware_mfa"), Op: predicate.OpEq},
					{Field: predicate.NewFieldPath("properties.identity.has_virtual_mfa"), Op: predicate.OpEq},
				},
			},
		},
	}

	paths, err := Extract(pred)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("paths = %d, want 3", len(paths))
	}
}
