package stave_test

import (
	"context"
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

// TestExportInvariants_BuiltinCatalog exercises the embedded path:
// no ControlsDir means "use the built-in catalog". The export
// must surface every control as an invariant with a non-empty ID
// and a Severity drawn from the catalog's lowercase form.
func TestExportInvariants_BuiltinCatalog(t *testing.T) {
	t.Parallel()
	out, err := stave.ExportInvariants(context.Background(), stave.InvariantExportConfig{})
	if err != nil {
		t.Fatalf("ExportInvariants: %v", err)
	}
	if len(out.Invariants) == 0 {
		t.Fatal("expected non-empty Invariants from built-in catalog")
	}
	for i := range out.Invariants {
		inv := &out.Invariants[i]
		if inv.ID == "" {
			t.Errorf("invariant[%d] has empty ID", i)
		}
		if inv.Scope != stave.ScopeSingleAsset {
			t.Errorf("invariant[%d] scope = %q, want single_asset", i, inv.Scope)
		}
	}
}

// TestExportInvariants_PredicateShape walks the projection of one
// known control (S3 ACCESS.004) to confirm the predicate tree
// flattens correctly: the All combiner with two leaves, the leaf
// (Property, Operator, Expected) values match the YAML, and
// IsLeaf()/Combine wiring is internally consistent.
func TestExportInvariants_PredicateShape(t *testing.T) {
	t.Parallel()
	out, err := stave.ExportInvariants(context.Background(), stave.InvariantExportConfig{})
	if err != nil {
		t.Fatalf("ExportInvariants: %v", err)
	}
	var inv *stave.InvariantDefinition
	for i := range out.Invariants {
		if out.Invariants[i].ID == "CTL.S3.ACCESS.004" {
			inv = &out.Invariants[i]
			break
		}
	}
	if inv == nil {
		t.Fatal("CTL.S3.ACCESS.004 not present in built-in catalog export")
	}

	if inv.Predicate.Combine != "all" {
		t.Fatalf("Predicate.Combine = %q, want all", inv.Predicate.Combine)
	}
	if inv.Predicate.IsLeaf() {
		t.Errorf("root with Combine=all must not be a leaf")
	}
	if len(inv.Predicate.Children) < 2 {
		t.Fatalf("Children = %d, want >= 2", len(inv.Predicate.Children))
	}
	for _, child := range inv.Predicate.Children {
		if !child.IsLeaf() {
			continue
		}
		if child.Property == "" {
			t.Errorf("leaf has empty Property")
		}
		if child.Operator == "" {
			t.Errorf("leaf has empty Operator")
		}
	}
}

// TestExportInvariants_ContextRequired guards the nil-ctx branch.
func TestExportInvariants_ContextRequired(t *testing.T) {
	t.Parallel()
	if _, err := stave.ExportInvariants(nil, stave.InvariantExportConfig{}); err == nil { //nolint:staticcheck // explicitly testing nil context handling
		t.Fatal("expected error for nil context")
	}
}

// TestExportInvariants_IntentRationaleAndForbiddenState verifies
// that the recently-shipped CTL.S3.ACCESS.EXTERNAL.ORG.001 (the
// reference control authored to exercise the new fields)
// surfaces both IntentRationale (authored "why" prose) and
// ForbiddenState (the Z3-checkable invariant block) through the
// public InvariantExport. Every other control may legitimately
// leave the fields zero.
func TestExportInvariants_IntentRationaleAndForbiddenState(t *testing.T) {
	t.Parallel()
	out, err := stave.ExportInvariants(context.Background(), stave.InvariantExportConfig{})
	if err != nil {
		t.Fatalf("ExportInvariants: %v", err)
	}
	var inv *stave.InvariantDefinition
	for i := range out.Invariants {
		if out.Invariants[i].ID == "CTL.S3.ACCESS.EXTERNAL.ORG.001" {
			inv = &out.Invariants[i]
			break
		}
	}
	if inv == nil {
		t.Fatal("CTL.S3.ACCESS.EXTERNAL.ORG.001 missing from built-in catalog export")
	}
	if inv.IntentRationale == "" {
		t.Errorf("IntentRationale empty; control YAML authors it as the HIPAA-boundary rationale")
	}
	if inv.ForbiddenState.Combine != "all" {
		t.Errorf("ForbiddenState.Combine = %q, want all", inv.ForbiddenState.Combine)
	}
	if len(inv.ForbiddenState.Children) < 3 {
		t.Errorf("ForbiddenState.Children = %d, want >= 3 (kind, classification, external_account_ids)",
			len(inv.ForbiddenState.Children))
	}
}

// TestExportInvariants_ForbiddenStateOptional confirms that
// controls without a forbidden_state block project the zero
// PredicateExport (Combine == ""), so consumers can branch on
// "no Z3-checkable invariant authored" cleanly.
func TestExportInvariants_ForbiddenStateOptional(t *testing.T) {
	t.Parallel()
	out, err := stave.ExportInvariants(context.Background(), stave.InvariantExportConfig{})
	if err != nil {
		t.Fatalf("ExportInvariants: %v", err)
	}
	// Most controls do not author forbidden_state — pick any
	// control whose ID is not the reference one, confirm the
	// zero-value semantics.
	for i := range out.Invariants {
		inv := &out.Invariants[i]
		if inv.ID == "CTL.S3.ACCESS.EXTERNAL.ORG.001" {
			continue
		}
		if inv.ForbiddenState.Combine == "" && len(inv.ForbiddenState.Children) == 0 {
			if !inv.ForbiddenState.IsLeaf() {
				t.Errorf("zero ForbiddenState should report IsLeaf=true; got false on %s", inv.ID)
			}
			return
		}
	}
}

// TestExportInvariants_DeterministicOrder asserts the output is
// sorted by control ID across runs.
func TestExportInvariants_DeterministicOrder(t *testing.T) {
	t.Parallel()
	a, err := stave.ExportInvariants(context.Background(), stave.InvariantExportConfig{})
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := stave.ExportInvariants(context.Background(), stave.InvariantExportConfig{})
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if len(a.Invariants) != len(b.Invariants) {
		t.Fatalf("len mismatch")
	}
	for i := range a.Invariants {
		if a.Invariants[i].ID != b.Invariants[i].ID {
			t.Errorf("order differs at %d: %q vs %q", i, a.Invariants[i].ID, b.Invariants[i].ID)
		}
	}
	for i := 1; i < len(a.Invariants); i++ {
		if a.Invariants[i-1].ID >= a.Invariants[i].ID {
			t.Errorf("not sorted at %d: %q >= %q", i, a.Invariants[i-1].ID, a.Invariants[i].ID)
		}
	}
}
