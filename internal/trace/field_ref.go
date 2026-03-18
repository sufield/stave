package trace

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/predicate"
)

// traceFieldRefRule traces neq_field, not_in_field, not_subset_of_field.
// All input data is pre-resolved in ruleContext; this function only
// records the result.
func traceFieldRefRule(rc ruleContext) Node {
	otherField := rc.OtherField
	if otherField.IsZero() {
		// CompareValue wasn't a string field path — malformed rule.
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

// fieldRefCompareFn is the final comparison applied after existence checks pass.
type fieldRefCompareFn func(fieldValue, otherValue any) bool

var fieldRefOps = map[predicate.Operator]struct {
	// missingField is the result when the source field doesn't exist.
	missingField bool
	// missingOther is the result when the other field doesn't exist
	// (but the source field does).
	missingOther bool
	compare      fieldRefCompareFn
}{
	predicate.OpNotSubsetOfField: {
		missingField: false,
		missingOther: true,
		compare:      predicate.ListHasElementsNotIn,
	},
	predicate.OpNeqField: {
		missingField: false,
		missingOther: true,
		compare:      func(a, b any) bool { return !predicate.EqualValues(a, b) },
	},
	predicate.OpNotInField: {
		missingField: true,
		missingOther: true,
		compare:      func(a, b any) bool { return !predicate.ValueInList(a, b) },
	},
}

func evaluateFieldRef(op predicate.Operator, fieldExists bool, fieldValue any, otherExists bool, otherValue any) bool {
	spec, ok := fieldRefOps[op]
	if !ok {
		return false
	}
	if !fieldExists {
		return spec.missingField
	}
	if !otherExists {
		return spec.missingOther
	}
	return spec.compare(fieldValue, otherValue)
}
