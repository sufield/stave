package trace

import (
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// ruleContext is a flat data carrier for a single predicate rule evaluation.
// All input data is pre-resolved so downstream tracers only record results.
type ruleContext struct {
	Index          int
	Field          predicate.FieldPath
	Op             predicate.Operator
	Value          any // raw from control
	ValueFromParam predicate.ParamRef
	CompareValue   any // after value_from_param resolution
	FieldValue     any // actual asset value
	FieldExists    bool
	EvalCtx        policy.EvalContext // needed by any-match tracer

	// Field-ref operators: pre-resolved other-field state.
	OtherField  predicate.FieldPath
	OtherValue  any
	OtherExists bool
}

func newRuleContext(index int, rule *policy.PredicateRule, evalCtx policy.EvalContext) ruleContext {
	fieldValue, fieldExists := policy.GetFieldValueWithContext(evalCtx, rule.Field.String())

	compareValue := rule.Value.Raw()
	if !rule.ValueFromParam.IsZero() {
		compareValue, _ = evalCtx.Param(rule.ValueFromParam.String())
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
	if rc.Op.IsFieldRef() {
		if path, ok := compareValue.(string); ok {
			rc.OtherField = predicate.NewFieldPath(path)
			rc.OtherValue, rc.OtherExists = policy.GetFieldValueWithContext(evalCtx, path)
		}
	}

	return rc
}
