package predicate

import (
	"cmp"
	"slices"
)

// Operator identifies a predicate comparison operator used in control rules.
// Operators are the domain contract between YAML/JSON control definitions
// and the evaluation engine (currently CEL). The engine adapter translates
// each Operator into its implementation-specific expression.
type Operator string

// Canonical predicate operator identifiers.
const (
	// OpEq matches when the field value equals the expected value.
	OpEq Operator = "eq"
	// OpNe matches when the field value does not equal the expected value.
	OpNe Operator = "ne"
	// OpGt matches when the field value is greater than the expected value.
	OpGt Operator = "gt"
	// OpLt matches when the field value is less than the expected value.
	OpLt Operator = "lt"
	// OpGte matches when the field value is greater than or equal.
	OpGte Operator = "gte"
	// OpLte matches when the field value is less than or equal.
	OpLte Operator = "lte"
	// OpMissing matches when the field does not exist in the asset properties.
	OpMissing Operator = "missing"
	// OpPresent matches when the field exists in the asset properties.
	OpPresent Operator = "present"
	// OpIn matches when the field value is contained in a list.
	OpIn Operator = "in"
	// OpListEmpty matches when the field is an empty list.
	OpListEmpty Operator = "list_empty"
	// OpNotSubsetOfField matches when the field is not a subset of another field's list.
	OpNotSubsetOfField Operator = "not_subset_of_field"
	// OpNeqField matches when the field value differs from another field's value.
	OpNeqField Operator = "neq_field"
	// OpNotInField matches when the field value is not in another field's list.
	OpNotInField Operator = "not_in_field"
	// OpContains matches when the field value contains a substring or element.
	OpContains Operator = "contains"
	// OpAnyMatch matches when any element in a list satisfies the condition.
	// Requires an explicit `field` referencing the list to iterate. See
	// OpAnyIdentityMatch for the identity-iterating shorthand.
	OpAnyMatch Operator = "any_match"
	// OpAnyIdentityMatch is the explicit form of "iterate the asset's
	// identities list and apply the nested predicate to each
	// identity." Equivalent to writing
	//   { field: identities, op: any_match, value: { ... } }
	// but more readable for the common identity-traversal case.
	OpAnyIdentityMatch Operator = "any_identity_match"
	// OpAnyInField matches when the field is a list containing at least one
	// element that also appears in another field's list. Used for
	// list-intersects-list checks where one side is typically a params
	// reference (e.g., a deny-list of service names checked against a
	// derived list on the principal). Both sides must be present and
	// resolve to lists; either missing → false. Complement of
	// OpNotSubsetOfField.
	OpAnyInField Operator = "any_in_field"
)

// supportedOps is the canonical registry. Sorted once at init for
// deterministic output from ListSupported.
var supportedOps = func() []Operator {
	ops := []Operator{
		OpEq, OpNe, OpGt, OpLt, OpGte, OpLte,
		OpMissing, OpPresent, OpIn, OpListEmpty,
		OpNotSubsetOfField, OpNeqField, OpNotInField,
		OpContains, OpAnyMatch, OpAnyIdentityMatch, OpAnyInField,
	}
	slices.SortFunc(ops, func(a, b Operator) int {
		return cmp.Compare(string(a), string(b))
	})
	return ops
}()

// IsSupported reports whether the operator is recognized by the engine.
func IsSupported(op Operator) bool {
	switch op {
	case OpEq, OpNe, OpGt, OpLt, OpGte, OpLte,
		OpMissing, OpPresent, OpIn, OpListEmpty, OpContains,
		OpNeqField, OpNotInField, OpNotSubsetOfField,
		OpAnyMatch, OpAnyIdentityMatch, OpAnyInField:
		return true
	}
	return false
}

// ListSupported returns all supported operators in deterministic alphabetical order.
// Returns a defensive copy to prevent mutation of the global registry.
func ListSupported() []Operator {
	return slices.Clone(supportedOps)
}

// ParamRef is a typed reference to a control parameter name. It replaces the
// raw string used in ValueFromParam, making parameter references explicit in
// the type system. As a named string type it marshals to/from YAML and JSON
// naturally.
type ParamRef string

// String returns the parameter name.
func (p ParamRef) String() string { return string(p) }

// IsZero reports whether the reference is empty. Supports yaml omitempty.
func (p ParamRef) IsZero() bool { return p == "" }
