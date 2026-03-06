package trace

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// traceFieldRefRule traces neq_field, not_in_field, not_subset_of_field.
func traceFieldRefRule(rc ruleContext) Node {
	otherFieldPath, ok := rc.CompareValue.(string)
	if !ok {
		return &FieldRefNode{
			Index:       rc.Index,
			Field:       rc.Field,
			Op:          rc.Op,
			OtherField:  fmt.Sprintf("%v", rc.CompareValue),
			FieldValue:  rc.FieldValue,
			FieldExists: rc.FieldExists,
			Result:      false,
		}
	}

	otherValue, otherExists := policy.GetFieldValueWithContext(rc.EvalCtx, otherFieldPath)
	result := evaluateFieldRefResult(rc.Op, rc.FieldExists, rc.FieldValue, otherExists, otherValue)

	return &FieldRefNode{
		Index:       rc.Index,
		Field:       rc.Field,
		Op:          rc.Op,
		OtherField:  otherFieldPath,
		FieldValue:  rc.FieldValue,
		OtherValue:  otherValue,
		FieldExists: rc.FieldExists,
		OtherExists: otherExists,
		Result:      result,
	}
}

func evaluateFieldRefResult(op string, fieldExists bool, fieldValue any, otherExists bool, otherValue any) bool {
	switch op {
	case predicate.OpNotSubsetOfField:
		return evalNotSubsetOfField(fieldExists, fieldValue, otherExists, otherValue)
	case predicate.OpNeqField:
		return evalNotEqualField(fieldExists, fieldValue, otherExists, otherValue)
	case predicate.OpNotInField:
		return evalNotInField(fieldExists, fieldValue, otherExists, otherValue)
	default:
		return false
	}
}

func evalNotSubsetOfField(fieldExists bool, fieldValue any, otherExists bool, otherValue any) bool {
	if !fieldExists {
		return false
	}
	if !otherExists {
		return true
	}
	return predicate.ListHasElementsNotIn(fieldValue, otherValue)
}

func evalNotEqualField(fieldExists bool, fieldValue any, otherExists bool, otherValue any) bool {
	if !fieldExists {
		return false
	}
	if !otherExists {
		return true
	}
	return !predicate.EqualValues(fieldValue, otherValue)
}

func evalNotInField(fieldExists bool, fieldValue any, otherExists bool, otherValue any) bool {
	if !fieldExists || !otherExists {
		return true
	}
	return !predicate.ValueInList(fieldValue, otherValue)
}
