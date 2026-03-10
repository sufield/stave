package trace

import (
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// ruleContext is a flat data carrier for a single predicate rule evaluation.
type ruleContext struct {
	Index          int
	Field          string
	Op             predicate.Operator
	Value          any // raw from control
	ValueFromParam string
	CompareValue   any // after value_from_param resolution
	FieldValue     any // actual asset value
	FieldExists    bool
	EvalCtx        policy.EvalContext // needed by field-ref and any-match tracers
}

func newRuleContext(index int, rule *policy.PredicateRule, evalCtx policy.EvalContext) ruleContext {
	fieldValue, fieldExists := policy.GetFieldValueWithContext(evalCtx, rule.Field)

	compareValue := rule.Value
	if rule.ValueFromParam != "" && evalCtx.Params != nil {
		compareValue = evalCtx.Params[rule.ValueFromParam]
	}

	return ruleContext{
		Index:          index,
		Field:          rule.Field,
		Op:             rule.Op,
		Value:          rule.Value,
		ValueFromParam: rule.ValueFromParam,
		CompareValue:   compareValue,
		FieldValue:     fieldValue,
		FieldExists:    fieldExists,
		EvalCtx:        evalCtx,
	}
}
