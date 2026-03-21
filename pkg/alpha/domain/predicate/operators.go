package predicate

import (
	"cmp"
	"slices"
)

// Operator identifies a predicate comparison operator (eq, ne, missing, etc.).
type Operator string

// Canonical predicate operator identifiers.
const (
	OpEq               Operator = "eq"
	OpNe               Operator = "ne"
	OpGt               Operator = "gt"
	OpLt               Operator = "lt"
	OpGte              Operator = "gte"
	OpLte              Operator = "lte"
	OpMissing          Operator = "missing"
	OpPresent          Operator = "present"
	OpIn               Operator = "in"
	OpListEmpty        Operator = "list_empty"
	OpNotSubsetOfField Operator = "not_subset_of_field"
	OpNeqField         Operator = "neq_field"
	OpNotInField       Operator = "not_in_field"
	OpContains         Operator = "contains"
	OpAnyMatch         Operator = "any_match"
)

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

// ListSupported returns all supported operators in deterministic order.
func ListSupported() []Operator {
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
}
