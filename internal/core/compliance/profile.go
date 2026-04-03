package compliance

import "fmt"

// IncompatiblePair documents two control IDs that must not appear
// in the same evaluation profile.
type IncompatiblePair struct {
	A      string
	B      string
	Reason string
}

// KnownIncompatible returns the compile-time list of control pairs that
// cannot coexist in a single profile.
func KnownIncompatible() []IncompatiblePair {
	return []IncompatiblePair{
		{
			A:      "CONTROLS.003",
			B:      "RETENTION.001",
			Reason: "MFA Delete (CONTROLS.003) and lifecycle expiry (RETENTION.001) are mutually exclusive — MFA Delete prevents lifecycle rules from permanently deleting objects",
		},
	}
}

// ValidateProfile checks that a set of control IDs contains no
// incompatible pairs. Returns an error at startup if a conflict is found.
func ValidateProfile(ids []string) error {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}

	for _, pair := range KnownIncompatible() {
		_, hasA := set[pair.A]
		_, hasB := set[pair.B]
		if hasA && hasB {
			return fmt.Errorf("profile conflict: %s and %s are incompatible — %s", pair.A, pair.B, pair.Reason)
		}
	}

	return nil
}
