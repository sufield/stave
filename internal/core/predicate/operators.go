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
	OpAnyMatch Operator = "any_match"
)

// supportedOps is the canonical registry. Sorted once at init for
// deterministic output from ListSupported.
var supportedOps = func() []Operator {
	ops := []Operator{
		OpEq, OpNe, OpGt, OpLt, OpGte, OpLte,
		OpMissing, OpPresent, OpIn, OpListEmpty,
		OpNotSubsetOfField, OpNeqField, OpNotInField,
		OpContains, OpAnyMatch,
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
		OpAnyMatch:
		return true
	}
	return false
}

// ListSupported returns all supported operators in deterministic alphabetical order.
// Returns a defensive copy to prevent mutation of the global registry.
func ListSupported() []Operator {
	return slices.Clone(supportedOps)
}
