package engine

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
	"github.com/sufield/stave/internal/platform/crypto"
)

// TestFingerprintPolicy_PredicateChangeDetected is the primary audit
// integrity test. It verifies that weakening a control predicate changes
// the fingerprint even when the control ID is unchanged.
//
// A fingerprint that only hashes IDs would pass all other fingerprint
// tests but fail this one — revealing the audit bypass.
func TestFingerprintPolicy_PredicateChangeDetected(t *testing.T) {
	strict := []policy.ControlDefinition{{
		ID:       "CTL.S3.PUBLIC.001",
		Severity: policy.SeverityCritical,
		Type:     policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{{
				Field: predicate.NewFieldPath("properties.access.public"),
				Op:    "eq",
				Value: policy.NewOperand(true),
			}},
		},
	}}

	weakened := []policy.ControlDefinition{{
		ID:       "CTL.S3.PUBLIC.001",
		Severity: policy.SeverityCritical,
		Type:     policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{{
				Field: predicate.NewFieldPath("properties.access.public"),
				Op:    "eq",
				Value: policy.NewOperand(false), // negated — always passes
			}},
		},
	}}

	a1 := &Assessor{Controls: strict, Hasher: crypto.NewHasher()}
	a2 := &Assessor{Controls: weakened, Hasher: crypto.NewHasher()}

	fp1 := a1.FingerprintPolicy()
	fp2 := a2.FingerprintPolicy()

	if fp1 == fp2 {
		t.Errorf(
			"CRITICAL AUDIT BYPASS: FingerprintPolicy produced identical "+
				"fingerprint %q for strict and weakened predicates. "+
				"An operator can weaken any control without detection.", fp1)
	}
}

// TestFingerprintPolicy_PredicateFieldPathMatters verifies that changing
// which field a predicate checks changes the fingerprint. This rules out
// implementations that hash the predicate value but ignore the field path.
func TestFingerprintPolicy_PredicateFieldPathMatters(t *testing.T) {
	a := []policy.ControlDefinition{{
		ID: "CTL.TEST.001", Severity: policy.SeverityHigh, Type: policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{All: []policy.PredicateRule{{
			Field: predicate.NewFieldPath("properties.encryption.enabled"),
			Op:    "eq", Value: policy.NewOperand(false),
		}}},
	}}
	b := []policy.ControlDefinition{{
		ID: "CTL.TEST.001", Severity: policy.SeverityHigh, Type: policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{All: []policy.PredicateRule{{
			Field: predicate.NewFieldPath("properties.logging.enabled"),
			Op:    "eq", Value: policy.NewOperand(false),
		}}},
	}}

	fp1 := (&Assessor{Controls: a, Hasher: crypto.NewHasher()}).FingerprintPolicy()
	fp2 := (&Assessor{Controls: b, Hasher: crypto.NewHasher()}).FingerprintPolicy()

	if fp1 == fp2 {
		t.Error("changing predicate field path did not change fingerprint")
	}
}
