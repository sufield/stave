package trace

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/predicate"
)

// traceFieldRefRule constructs a trace node for field-to-field comparison operators
// such as neq_field, not_in_field, or not_subset_of_field.
func traceFieldRefRule(rc ruleContext) Node {
	otherField := rc.OtherField
	if otherField.IsZero() {
		otherField = predicate.NewFieldPath(fmt.Sprintf("%v", rc.CompareValue))
	}

	return &FieldRefNode{
		Index:       rc.Index,
		Field:       rc.Field,
		Op:          rc.Op,
		OtherField:  otherField,
		ActualValue: rc.FieldValue,
		OtherValue:  rc.OtherValue,
		FieldExists: rc.FieldExists,
		OtherExists: rc.OtherExists,
		Result:      evaluateFieldRef(rc.Op, rc.FieldExists, rc.FieldValue, rc.OtherExists, rc.OtherValue),
	}
}

// evaluateFieldRef performs the comparison for field-ref operators,
// handling "fail closed" semantics for missing fields.
func evaluateFieldRef(op predicate.Operator, exists bool, val any, otherExists bool, otherVal any) bool {
	switch op {
	case predicate.OpNotSubsetOfField:
		if !exists {
			return false
		}
		if !otherExists {
			return true
		}
		return predicate.ListHasElementsNotIn(val, otherVal)

	case predicate.OpNeqField:
		if !exists {
			return false
		}
		if !otherExists {
			return true
		}
		return !predicate.EqualValues(val, otherVal)

	case predicate.OpNotInField:
		if !exists || !otherExists {
			return true
		}
		return !predicate.ValueInList(val, otherVal)

	default:
		return false
	}
}
