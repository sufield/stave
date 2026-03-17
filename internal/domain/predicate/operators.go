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

// --- Operator behavior methods ---

// IsStandard reports whether the operator is handled entirely by EvaluateOperator
// (i.e. requires no external context such as field-to-field comparison).
func (op Operator) IsStandard() bool {
	switch op {
	case OpEq, OpNe, OpGt, OpLt, OpGte, OpLte,
		OpMissing, OpPresent, OpIn, OpListEmpty, OpContains:
		return true
	}
	return false
}

// IsFieldRef reports whether the operator compares the field's value against
// another field's value (e.g. neq_field, not_in_field, not_subset_of_field).
func (op Operator) IsFieldRef() bool {
	switch op {
	case OpNeqField, OpNotInField, OpNotSubsetOfField:
		return true
	}
	return false
}

// IsPresenceBased reports whether the operator checks field presence or absence
// rather than comparing field values (missing, present).
func (op Operator) IsPresenceBased() bool {
	switch op {
	case OpMissing, OpPresent:
		return true
	}
	return false
}

// RequiresNestedPredicate reports whether the operator expects a nested
// predicate structure as its comparison value (any_match).
func (op Operator) RequiresNestedPredicate() bool {
	return op == OpAnyMatch
}

// IsSupported reports whether the operator is recognized by the engine.
func IsSupported(op Operator) bool {
	return op.IsStandard() || op.IsFieldRef() || op.RequiresNestedPredicate()
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

// Evaluate performs a basic operator check assuming the field is present.
func Evaluate(op Operator, fieldVal, matchVal any) bool {
	result, handled := EvaluateOperator(op, true, fieldVal, matchVal)
	return handled && result
}

// EvaluateOperator handles standard data-driven operators.
// It returns (result, handled). If handled is false, the operator requires
// external context (like field-to-field comparison) handled by the caller.
func EvaluateOperator(op Operator, exists bool, val, compare any) (res bool, handled bool) {
	switch op {
	case OpEq:
		res = exists && EqualValues(val, compare)
	case OpNe:
		res = !exists || !EqualValues(val, compare)
	case OpGt:
		res = exists && GreaterThan(val, compare)
	case OpLt:
		res = exists && LessThan(val, compare)
	case OpGte:
		res = exists && GreaterThanOrEqual(val, compare)
	case OpLte:
		res = exists && LessThanOrEqual(val, compare)

	case OpMissing:
		wantMissing, _ := ToBool(compare)
		isMissing := !exists || val == nil || IsEmptyValue(val)
		res = isMissing == wantMissing

	case OpPresent:
		wantPresent, _ := ToBool(compare)
		isPresent := exists && val != nil && !IsEmptyValue(val)
		res = isPresent == wantPresent

	case OpIn:
		res = exists && ValueInList(val, compare)

	case OpListEmpty:
		wantEmpty, _ := ToBool(compare)
		isEmpty := !exists || IsEmptyList(val)
		res = isEmpty == wantEmpty

	case OpContains:
		res = exists && StringContains(val, compare)

	case OpNotSubsetOfField, OpNeqField, OpNotInField, OpAnyMatch:
		return false, false

	default:
		return false, false
	}

	return res, true
}
