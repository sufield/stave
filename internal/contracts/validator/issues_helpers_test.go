package validator

import "github.com/santhosh-tekuri/jsonschema/v6/kind"

// IsUnknownFieldDiagnostic reports whether a diagnostic represents an
// additional-properties violation (i.e., an unknown field).
func IsUnknownFieldDiagnostic(d Diagnostic) bool {
	if d.Kind == nil {
		return false
	}
	_, ok := d.Kind.(*kind.AdditionalProperties)
	return ok
}
