package trace

import (
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// ruleContext is a flat data carrier for a single predicate rule evaluation.
// All input data is pre-resolved so downstream tracers only record results.
type ruleContext struct {
	Index          int
	Field          string
	Op             predicate.Operator
	Value          any // raw from control
	ValueFromParam string
	CompareValue   any // after value_from_param resolution
	FieldValue     any // actual asset value
	FieldExists    bool
	EvalCtx        policy.EvalContext // needed by any-match tracer

	// Field-ref operators: pre-resolved other-field state.
	OtherField  string
	OtherValue  any
	OtherExists bool
}

func newRuleContext(index int, rule *policy.PredicateRule, evalCtx policy.EvalContext) ruleContext {
	fieldValue, fieldExists := policy.GetFieldValueWithContext(evalCtx, rule.Field)

	compareValue := rule.Value.Raw()
	if rule.ValueFromParam != "" {
		compareValue, _ = evalCtx.Param(rule.ValueFromParam)
	}

	rc := ruleContext{
		Index:          index,
		Field:          rule.Field,
		Op:             rule.Op,
		Value:          rule.Value.Raw(),
		ValueFromParam: rule.ValueFromParam,
		CompareValue:   compareValue,
		FieldValue:     fieldValue,
		FieldExists:    fieldExists,
		EvalCtx:        evalCtx,
	}

	// Pre-resolve the other-field for field-ref operators so tracers
	// don't need to reach back into the EvalContext.
	if isFieldRefOp(rc.Op) {
		if path, ok := compareValue.(string); ok {
			rc.OtherField = path
			rc.OtherValue, rc.OtherExists = policy.GetFieldValueWithContext(evalCtx, path)
		}
	}

	return rc
}

func isFieldRefOp(op predicate.Operator) bool {
	switch op {
	case predicate.OpNeqField, predicate.OpNotInField, predicate.OpNotSubsetOfField:
		return true
	default:
		return false
	}
}
