package predicate

import "sort"

// Canonical predicate operator identifiers.
const (
	OpEq               = "eq"
	OpNe               = "ne"
	OpGt               = "gt"
	OpLt               = "lt"
	OpGte              = "gte"
	OpLte              = "lte"
	OpMissing          = "missing"
	OpPresent          = "present"
	OpIn               = "in"
	OpListEmpty        = "list_empty"
	OpNotSubsetOfField = "not_subset_of_field"
	OpNeqField         = "neq_field"
	OpNotInField       = "not_in_field"
	OpContains         = "contains"
	OpAnyMatch         = "any_match"
)

// operatorFunc handles evaluation logic for a specific operator.
type operatorFunc func(fieldExists bool, fieldVal, matchVal any) (bool, bool)

func handled(fn func(fieldExists bool, fieldVal, matchVal any) bool) operatorFunc {
	return func(fieldExists bool, fieldVal, matchVal any) (bool, bool) {
		return fn(fieldExists, fieldVal, matchVal), true
	}
}

func delegated(bool, any, any) (bool, bool) {
	return false, false
}

// operators is the internal source of truth for operator behavior.
var operators = map[string]operatorFunc{
	OpEq:  handled(func(exists bool, f, m any) bool { return exists && EqualValues(f, m) }),
	OpNe:  handled(func(exists bool, f, m any) bool { return !exists || !EqualValues(f, m) }),
	OpGt:  handled(func(exists bool, f, m any) bool { return exists && GreaterThan(f, m) }),
	OpLt:  handled(func(exists bool, f, m any) bool { return exists && LessThan(f, m) }),
	OpGte: handled(func(exists bool, f, m any) bool { return exists && GreaterThanOrEqual(f, m) }),
	OpLte: handled(func(exists bool, f, m any) bool { return exists && LessThanOrEqual(f, m) }),
	OpMissing: handled(func(exists bool, f, m any) bool {
		wantMissing, _ := m.(bool)
		isMissing := !exists || f == nil || IsEmptyValue(f)
		return isMissing == wantMissing
	}),
	OpPresent: handled(func(exists bool, f, m any) bool {
		wantPresent, _ := m.(bool)
		isPresent := exists && !IsEmptyValue(f)
		return isPresent == wantPresent
	}),
	OpIn: handled(func(exists bool, f, m any) bool {
		return exists && ValueInList(f, m)
	}),
	OpListEmpty: handled(func(exists bool, f, m any) bool {
		wantEmpty, _ := m.(bool)
		isEmpty := !exists || IsEmptyList(f)
		return isEmpty == wantEmpty
	}),
	OpContains: handled(func(exists bool, f, m any) bool {
		return exists && StringContains(f, m)
	}),

	// Context-dependent operators are supported, but delegated to caller logic.
	OpNotSubsetOfField: delegated,
	OpNeqField:         delegated,
	OpNotInField:       delegated,
	OpAnyMatch:         delegated,
}

// IsSupported returns true if the operator is supported.
func IsSupported(op string) bool {
	_, ok := operators[op]
	return ok
}

// ListSupported returns all supported operators in deterministic order.
func ListSupported() []string {
	ops := make([]string, 0, len(operators))
	for op := range operators {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return ops
}

// Evaluate maps basic operators to semantic comparison functions.
// Unknown operators fail closed.
func Evaluate(op string, fieldVal, matchVal any) bool {
	const fieldIsPresent = true
	result, handled := EvaluateOperator(op, fieldIsPresent, fieldVal, matchVal)
	return handled && result
}

// EvaluateOperator evaluates operators that do not require external context.
// Returns (result, handled). If handled is false, caller should evaluate with
// additional context-specific logic.
func EvaluateOperator(op string, fieldExists bool, fieldValue, compareValue any) (bool, bool) {
	fn, ok := operators[op]
	if !ok {
		return false, false
	}
	return fn(fieldExists, fieldValue, compareValue)
}
