// Package trace walks an control's unsafe_predicate clause by clause
// against a single asset and captures a detailed evaluation tree.
package trace

import (
	"fmt"
	"io"
	"sync"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// LogicType represents the logical combination mode for a predicate group.
type LogicType int

const (
	LogicEmpty     LogicType = iota // no predicate rules defined
	LogicAny                        // at least one rule must match
	LogicAll                        // every rule must match
	LogicAnyAndAll                  // any block checked first, then all block
)

func (lt LogicType) String() string {
	switch lt {
	case LogicAny:
		return "any"
	case LogicAll:
		return "all"
	case LogicAnyAndAll:
		return "any+all"
	default:
		return "empty"
	}
}

// Node is a single node in the trace tree.
// The unexported methods seal the interface: only types in this package
// can implement Node, guaranteeing exhaustive handling in formatters.
type Node interface {
	Matched() bool
	renderText(tw *TextWriter)
	toJSON() jsonNode
}

// TraceResult is the top-level output of a trace.
type TraceResult struct {
	ControlID   kernel.ControlID
	AssetID     asset.ID
	Properties  map[string]any
	Params      policy.ControlParams
	Root        *GroupNode
	FinalResult bool
}

// GroupNode represents an "any" or "all" group.
type GroupNode struct {
	Logic             LogicType
	Children          []Node
	Result            bool
	ShortCircuitIndex int    // index where short-circuit fired, -1 if exhaustive
	Reason            string // e.g. "Clause 2 failed in all → NO MATCH"
}

func (g *GroupNode) Matched() bool { return g.Result }

// ClauseNode is a leaf field comparison (standard operators).
type ClauseNode struct {
	Index          int
	Field          string
	Op             string
	Value          any // raw from control
	ResolvedValue  any // after value_from_param resolution
	FieldValue     any // actual asset value
	ValueFromParam string
	FieldExists    bool
	Result         bool
}

func (c *ClauseNode) Matched() bool { return c.Result }

// FieldRefNode represents neq_field, not_in_field, not_subset_of_field.
type FieldRefNode struct {
	Index       int
	Field       string
	Op          string
	OtherField  string
	FieldValue  any
	OtherValue  any
	FieldExists bool
	OtherExists bool
	Result      bool
}

func (f *FieldRefNode) Matched() bool { return f.Result }

// AnyMatchNode represents an any_match with identity iteration.
type AnyMatchNode struct {
	Index         int
	Field         string
	FieldExists   bool
	IdentityCount int
	MatchedIndex  *int
	MatchedID     string
	NestedTrace   *GroupNode
	Result        bool
}

func (a *AnyMatchNode) Matched() bool { return a.Result }

// RenderText renders the trace result as indented human-readable text.
func (tr *TraceResult) RenderText(w io.Writer) error { return WriteText(w, tr) }

// RenderJSON renders the trace result as structured JSON.
func (tr *TraceResult) RenderJSON(w io.Writer) error { return WriteJSON(w, tr) }

// operatorTracers maps operator names to specialized tracing functions.
// Initialized via sync.Once to avoid an initialization cycle (traceAnyMatchRule
// transitively references operatorTracers through TracePredicate).
var (
	operatorTracers     map[string]func(ruleContext) Node
	initOperatorTracers sync.Once
)

func ensureOperatorTracers() {
	initOperatorTracers.Do(func() {
		operatorTracers = map[string]func(ruleContext) Node{
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
