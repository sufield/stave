package trace

import (
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// ruleContext captures the full pre-resolved state of a single predicate rule
// evaluation. Downstream tracers only record results — they never reach back
// into the EvalContext for field lookups.
type ruleContext struct {
	// Rule definition
	Index          int
	Field          predicate.FieldPath
	Op             predicate.Operator
	Value          any               // raw value from policy definition
	ValueFromParam predicate.ParamRef // parameter reference, if used

	// Resolved match state
	CompareValue any  // resolved value used for comparison (param or raw)
	FieldValue   any  // actual value found on the asset
	FieldExists  bool // whether the field was present on the asset

	// Field-ref state (pre-resolved for neq_field, not_in_field, etc.)
	OtherField  predicate.FieldPath
	OtherValue  any
	OtherExists bool

	// Retained for complex tracers (any_match needs to build nested contexts)
	EvalCtx policy.EvalContext
}

func newRuleContext(index int, rule *policy.PredicateRule, ctx policy.EvalContext) ruleContext {
	fieldValue, fieldExists := policy.GetFieldValueWithContext(ctx, rule.Field.String())

	rc := ruleContext{
		Index:          index,
		Field:          rule.Field,
		Op:             rule.Op,
		Value:          rule.Value.Raw(),
		ValueFromParam: rule.ValueFromParam,
		CompareValue:   resolveCompareValue(rule, ctx),
		FieldValue:     fieldValue,
		FieldExists:    fieldExists,
		EvalCtx:        ctx,
	}

	if rc.Op.IsFieldRef() {
		rc.resolveFieldRef(ctx)
	}

	return rc
}

// resolveCompareValue determines whether to use the hardcoded value or a parameter.
func resolveCompareValue(rule *policy.PredicateRule, ctx policy.EvalContext) any {
	if rule.ValueFromParam.IsZero() {
		return rule.Value.Raw()
	}
	val, _ := ctx.Param(rule.ValueFromParam.String())
	return val
}

// resolveFieldRef populates the OtherField/OtherValue/OtherExists fields
// for operators that compare the primary field against another field.
func (rc *ruleContext) resolveFieldRef(ctx policy.EvalContext) {
	path, ok := rc.CompareValue.(string)
	if !ok {
		return
	}
	rc.OtherField = predicate.NewFieldPath(path)
	rc.OtherValue, rc.OtherExists = policy.GetFieldValueWithContext(ctx, path)
}
