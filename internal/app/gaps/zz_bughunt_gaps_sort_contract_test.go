package gaps

import (
	"testing"
)

func TestBugHunt_Prioritize_StrictWeakOrdering(t *testing.T) {
	// Create two FieldGaps with different non-tag remediation types
	a := FieldGap{
		IsIntentProperty: true,
	}
	a.Remediation.Type = "collector"

	b := FieldGap{
		IsIntentProperty: true,
	}
	b.Remediation.Type = "agent"

	// We pass a slice of [a, b] to a sorting wrapper that calls the comparator.
	// Since we want to check the comparator logic directly, we can run it.
	// Let's find the comparator function used in Prioritize.
	// Since it's inline in Prioritize, we can check if sorting [a, b] vs [b, a]
	// produces inconsistent results or violates symmetry.

	// A correct comparator must satisfy: compare(x, y) == -compare(y, x) for all x, y.
	// Let's test the sorting behavior with a small slice.
	slice1 := []FieldGap{a, b}
	Prioritize(slice1)

	slice2 := []FieldGap{b, a}
	Prioritize(slice2)

	// Since a and b are identical in all other fields (IsIntentProperty is true,
	// MaxSeverity, ChainsBlockedCount, MissingCount, PropertyPath, AssetType are all zero/empty),
	// they should be sorted deterministically.
	// If the comparator is symmetric, both slice1 and slice2 must result in the same order.
	if slice1[0].Remediation.Type != slice2[0].Remediation.Type {
		t.Errorf("non-deterministic sorting due to asymmetric comparator: slice1 got %q, slice2 got %q",
			slice1[0].Remediation.Type, slice2[0].Remediation.Type)
	}
}
