package trace

import (
	"fmt"
	"sync"

	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// operatorTracers maps operator names to specialized tracing functions.
// Initialized via sync.Once to avoid an initialization cycle (traceAnyMatchRule
// transitively references operatorTracers through TracePredicate).
var (
	operatorTracers     map[predicate.Operator]func(ruleContext) Node
	initOperatorTracers sync.Once
)

func ensureOperatorTracers() {
	initOperatorTracers.Do(func() {
		operatorTracers = map[predicate.Operator]func(ruleContext) Node{
			predicate.OpNotSubsetOfField: traceFieldRefRule,
			predicate.OpNeqField:         traceFieldRefRule,
			predicate.OpNotInField:       traceFieldRefRule,
			predicate.OpAnyMatch:         traceAnyMatchRule,
		}
	})
}

// TracePredicate traces the evaluation of an unsafe_predicate against an EvalContext.
func TracePredicate(pred policy.UnsafePredicate, ctx policy.EvalContext) *GroupNode {
	hasAny := len(pred.Any) > 0
	hasAll := len(pred.All) > 0

	if !hasAny && !hasAll {
		return &GroupNode{
			Logic:             LogicEmpty,
			ShortCircuitIndex: -1,
			Result:            false,
			Reason:            "No predicate rules defined → NO MATCH",
		}
	}

	if hasAny && !hasAll {
		return traceGroup(LogicAny, pred.Any, ctx)
	}

	if !hasAny && hasAll {
		return traceGroup(LogicAll, pred.All, ctx)
	}

	anyGroup := traceGroup(LogicAny, pred.Any, ctx)
	allGroup := traceGroup(LogicAll, pred.All, ctx)

	result := anyGroup.Result || allGroup.Result
	return &GroupNode{
		Logic:             LogicAnyAndAll,
		ShortCircuitIndex: -1,
		Children:          []Node{anyGroup, allGroup},
		Result:            result,
		Reason:            formatCombinedReason(anyGroup, allGroup),
	}
}

func formatCombinedReason(anyGroup, allGroup *GroupNode) string {
	if anyGroup.Result {
		return "any block matched → MATCH (all block not decisive)"
	}
	if allGroup.Result {
		return "any block did not match, all block matched → MATCH"
	}
	return "neither any nor all block matched → NO MATCH"
}

// traceGroup walks a slice of rules under "any" or "all" logic.
func traceGroup(logic LogicType, rules []policy.PredicateRule, ctx policy.EvalContext) *GroupNode {
	g := &GroupNode{
		Logic:             logic,
		ShortCircuitIndex: -1,
	}

	for i := range rules {
		child := traceRule(i, &rules[i], ctx)
		g.Children = append(g.Children, child)

		if logic == LogicAny && child.Matched() {
			g.ShortCircuitIndex = i
			g.Result = true
			g.Reason = fmt.Sprintf("Clause %d matched in any → MATCH", i+1)
			return g
		}
		if logic == LogicAll && !child.Matched() {
			g.ShortCircuitIndex = i
			g.Result = false
			g.Reason = fmt.Sprintf("Clause %d failed in all → NO MATCH", i+1)
			return g
		}
	}

	if logic == LogicAny {
		g.Result = false
		g.Reason = "No clause matched in any → NO MATCH"
	} else {
		g.Result = true
		g.Reason = "All clauses passed → MATCH"
	}
	return g
}

// traceRule traces a single predicate rule.
func traceRule(index int, rule *policy.PredicateRule, ctx policy.EvalContext) Node {
	ensureOperatorTracers()

	if len(rule.Any) > 0 {
		return traceGroup(LogicAny, rule.Any, ctx)
	}
	if len(rule.All) > 0 {
		return traceGroup(LogicAll, rule.All, ctx)
	}

	rc := newRuleContext(index, rule, ctx)

	if rc.ValueFromParam != "" && rc.CompareValue == nil {
		return buildClauseNode(rc, false)
	}

	if tracer, ok := operatorTracers[rc.Op]; ok {
		return tracer(rc)
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
		FieldValue:     rc.FieldValue,
		ValueFromParam: rc.ValueFromParam,
		FieldExists:    rc.FieldExists,
		Result:         result,
	}
}
