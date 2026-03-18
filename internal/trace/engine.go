package trace

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// TracePredicate builds a logical trace tree of how a predicate evaluated against an asset.
func TracePredicate(pred policy.UnsafePredicate, ctx policy.EvalContext) *GroupNode {
	hasAny := len(pred.Any) > 0
	hasAll := len(pred.All) > 0

	if !hasAny && !hasAll {
		return &GroupNode{
			Logic:             LogicEmpty,
			ShortCircuitIndex: -1,
			Result:            false,
			Reason:            "No rules defined; evaluating as safe",
		}
	}

	if hasAny && !hasAll {
		return traceGroup(LogicAny, pred.Any, ctx)
	}
	if !hasAny && hasAll {
		return traceGroup(LogicAll, pred.All, ctx)
	}

	anyNode := traceGroup(LogicAny, pred.Any, ctx)
	allNode := traceGroup(LogicAll, pred.All, ctx)

	return &GroupNode{
		Logic:             LogicMixed,
		ShortCircuitIndex: -1,
		Children:          []Node{anyNode, allNode},
		Result:            anyNode.Result || allNode.Result,
		Reason:            formatCombinedReason(anyNode, allNode),
	}
}

func formatCombinedReason(anyNode, allNode *GroupNode) string {
	switch {
	case anyNode.Result:
		return "Match found in 'any' block; 'all' block not decisive"
	case allNode.Result:
		return "No match in 'any' block, but 'all' block satisfied"
	default:
		return "Neither 'any' nor 'all' blocks satisfied criteria"
	}
}

// traceGroup evaluates a slice of rules under a specific logic gate (OR/AND).
func traceGroup(logic LogicType, rules []policy.PredicateRule, ctx policy.EvalContext) *GroupNode {
	g := &GroupNode{
		Logic:             logic,
		ShortCircuitIndex: -1,
		Children:          make([]Node, 0, len(rules)),
	}

	for i := range rules {
		child := traceRule(i, &rules[i], ctx)
		g.Children = append(g.Children, child)

		if logic == LogicAny && child.Matched() {
			g.ShortCircuitIndex = i
			g.Result = true
			g.Reason = fmt.Sprintf("Rule %d matched in 'any' block → MATCH", i+1)
			return g
		}
		if logic == LogicAll && !child.Matched() {
			g.ShortCircuitIndex = i
			g.Result = false
			g.Reason = fmt.Sprintf("Rule %d failed in 'all' block → NO MATCH", i+1)
			return g
		}
	}

	if logic == LogicAny {
		g.Result = false
		g.Reason = "No rules matched in 'any' block"
	} else {
		g.Result = true
		g.Reason = "All rules satisfied in 'all' block"
	}
	return g
}

// traceRule dispatches a single rule to the correct tracer based on its operator.
func traceRule(index int, rule *policy.PredicateRule, ctx policy.EvalContext) Node {
	if len(rule.Any) > 0 {
		return traceGroup(LogicAny, rule.Any, ctx)
	}
	if len(rule.All) > 0 {
		return traceGroup(LogicAll, rule.All, ctx)
	}

	rc := newRuleContext(index, rule, ctx)

	if !rc.ValueFromParam.IsZero() && rc.CompareValue == nil {
		return buildClauseNode(rc, false)
	}

	switch rc.Op {
	case predicate.OpAnyMatch:
		return traceAnyMatchRule(rc)
	case predicate.OpNotSubsetOfField, predicate.OpNeqField, predicate.OpNotInField:
		return traceFieldRefRule(rc)
	}

	result, _ := predicate.EvaluateOperator(rc.Op, rc.FieldExists, rc.FieldValue, rc.CompareValue)
	return buildClauseNode(rc, result)
}

func buildClauseNode(rc ruleContext, result bool) *ClauseNode {
	return &ClauseNode{
		Index:          rc.Index,
		Field:          rc.Field,
		Op:             rc.Op,
		Value:          rc.Value,
		ResolvedValue:  rc.CompareValue,
		ActualValue:    rc.FieldValue,
		ValueFromParam: rc.ValueFromParam,
		FieldExists:    rc.FieldExists,
		Result:         result,
	}
}
