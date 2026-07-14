package fieldcov

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// TestBugHunt_ScalarParentPrefix proves that fieldPresent wrongly treats a
// deeper child field as PRESENT when the snapshot only has a scalar at the
// parent path.
//
// Scenario: a control predicate references "properties.encryption.enabled"
// (silent-risk operator OpEq). The snapshot has a SCALAR value at
// "properties.encryption" — there is no nested object, so the leaf path
// "properties.encryption.enabled" was never collected.
//
// walkProperties records every map key, so the set contains
// "properties.encryption" (the scalar key). fieldPresent then matches via
// strings.HasPrefix("properties.encryption.enabled", "properties.encryption.")
// and reports the deeper field PRESENT — producing a wrong EVALUABLE verdict.
//
// Correct behavior: a nested field is present only if its exact leaf path was
// collected. The deeper field must be MISSING, so the control classifies as
// SilentRisk (not Evaluable).
func TestBugHunt_ScalarParentPrefix(t *testing.T) {
	// Snapshot: "encryption" is a scalar (bool), NOT a nested object.
	// So walkProperties collects "properties.encryption" but never
	// "properties.encryption.enabled".
	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Properties: map[string]any{
						"encryption": true,
					},
				},
			},
		},
	}

	presentFields := collectPresentFields(snapshots)

	// Sanity: confirm the test fixture really has the scalar-parent shape the
	// bug requires (parent collected, leaf not collected). These are not the
	// bug assertions — they guard against a contrived/always-fail test.
	if _, ok := presentFields["properties.encryption"]; !ok {
		t.Fatalf("fixture invalid: expected parent path %q to be collected", "properties.encryption")
	}
	if _, ok := presentFields["properties.encryption.enabled"]; ok {
		t.Fatalf("fixture invalid: leaf path %q should NOT be collected for a scalar parent",
			"properties.encryption.enabled")
	}

	ctl := policy.ControlDefinition{
		ID:       "CTL.BUGHUNT.001",
		Severity: policy.SeverityCritical,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.encryption.enabled"), Op: predicate.OpEq},
			},
		},
	}

	result := classifyControl(&ctl, presentFields, nil)

	// Correct behavior: the leaf field is MISSING, so the control is a silent
	// risk (an unguarded eq on an absent field may yield a false PASS).
	if result.Classification != SilentRisk {
		t.Fatalf("classification = %q, want %q: a scalar parent path must NOT satisfy presence of a deeper child field (properties.encryption.enabled)",
			result.Classification, SilentRisk)
	}
	if len(result.MissingFields) != 1 || result.MissingFields[0] != "properties.encryption.enabled" {
		t.Fatalf("missing fields = %v, want [properties.encryption.enabled]", result.MissingFields)
	}
}
