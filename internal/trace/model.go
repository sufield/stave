package trace

import (
	"io"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// LogicType represents the logical combination mode for a predicate group.
type LogicType int

const (
	LogicEmpty LogicType = iota // no predicate rules defined
	LogicAny                    // at least one rule must match
	LogicAll                    // every rule must match
	LogicMixed                  // both any and all blocks present
)

func (lt LogicType) String() string {
	switch lt {
	case LogicAny:
		return "any"
	case LogicAll:
		return "all"
	case LogicMixed:
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
	sealed()
}

// Compile-time interface assertions.
var (
	_ Node                     = (*GroupNode)(nil)
	_ Node                     = (*ClauseNode)(nil)
	_ Node                     = (*FieldRefNode)(nil)
	_ Node                     = (*AnyMatchNode)(nil)
	_ evaluation.TraceRenderer = (*Result)(nil)
)

// Result is the top-level output of a trace.
type Result struct {
	ControlID   kernel.ControlID
	AssetID     asset.ID
	Properties  map[string]any
	Params      policy.ControlParams
	Root        *GroupNode
	FinalResult bool
}

// RenderText renders the trace result as indented human-readable text.
func (r *Result) RenderText(w io.Writer) error { return WriteText(w, r) }

// RenderJSON renders the trace result as structured JSON.
func (r *Result) RenderJSON(w io.Writer) error { return WriteJSON(w, r) }

// GroupNode represents an "any" or "all" group.
type GroupNode struct {
	Logic             LogicType
	Children          []Node
	Result            bool
	ShortCircuitIndex int    // index where short-circuit fired, -1 if exhaustive
	Reason            string // e.g. "Clause 2 failed in all → NO MATCH"
}

func (g *GroupNode) Matched() bool { return g.Result }
func (*GroupNode) sealed()         {}

// ClauseNode is a leaf field comparison (standard operators).
type ClauseNode struct {
	Index          int
	Field          predicate.FieldPath
	Op             predicate.Operator
	Value          any // raw from control
	ResolvedValue  any // after value_from_param resolution
	ActualValue    any // Observed value from the asset
	ValueFromParam predicate.ParamRef
	FieldExists    bool
	Result         bool
}

func (c *ClauseNode) Matched() bool { return c.Result }
func (*ClauseNode) sealed()         {}

// FieldRefNode represents neq_field, not_in_field, not_subset_of_field.
type FieldRefNode struct {
	Index       int
	Field       predicate.FieldPath
	Op          predicate.Operator
	OtherField  predicate.FieldPath
	ActualValue any
	OtherValue  any
	FieldExists bool
	OtherExists bool
	Result      bool
}

func (f *FieldRefNode) Matched() bool { return f.Result }
func (*FieldRefNode) sealed()         {}

// AnyMatchNode represents an any_match with identity iteration.
type AnyMatchNode struct {
	Index         int
	Field         predicate.FieldPath
	FieldExists   bool
	IdentityCount int
	MatchedIndex  int
	MatchedID     asset.ID
	NestedTrace   *GroupNode
	Result        bool
}

func (a *AnyMatchNode) Matched() bool { return a.Result }
func (*AnyMatchNode) sealed()         {}
