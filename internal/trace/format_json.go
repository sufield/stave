package trace

import (
	"io"

	"github.com/sufield/stave/internal/domain/predicate"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// jsonResult is the top-level JSON output.
type jsonResult struct {
	ControlID   string         `json:"control_id"`
	AssetID     string         `json:"asset_id"`
	Properties  map[string]any `json:"properties"`
	Root        jsonNode       `json:"root"`
	FinalResult bool           `json:"final_result"`
}

// nodeKind discriminates the JSON union type for trace nodes.
type nodeKind string

const (
	kindGroup    nodeKind = "group"
	kindClause   nodeKind = "clause"
	kindFieldRef nodeKind = "field_ref"
	kindAnyMatch nodeKind = "any_match"
)

// jsonNode is a flat union type discriminated by "kind".
type jsonNode struct {
	Kind nodeKind `json:"kind"`

	// group fields
	Logic        string     `json:"logic,omitempty"`
	Children     []jsonNode `json:"children,omitempty"`
	ShortCircuit *int       `json:"short_circuit,omitempty"`
	Reason       string     `json:"reason,omitempty"`

	// clause fields
	Index          *int               `json:"index,omitempty"`
	Field          string             `json:"field,omitempty"`
	Op             predicate.Operator `json:"op,omitempty"`
	Value          any                `json:"value,omitempty"`
	ResolvedValue  any                `json:"resolved_value,omitempty"`
	FieldValue     any                `json:"field_value,omitempty"`
	ValueFromParam string             `json:"value_from_param,omitempty"`
	FieldExists    *bool              `json:"field_exists,omitempty"`
	Explanation    string             `json:"explanation,omitempty"`

	// field_ref fields
	OtherField  string `json:"other_field,omitempty"`
	OtherValue  any    `json:"other_value,omitempty"`
	OtherExists *bool  `json:"other_exists,omitempty"`

	// any_match fields
	IdentityCount *int      `json:"identity_count,omitempty"`
	MatchedIndex  *int      `json:"matched_index,omitempty"`
	MatchedID     string    `json:"matched_id,omitempty"`
	NestedTrace   *jsonNode `json:"nested_trace,omitempty"`

	// common
	Result bool `json:"result"`
}

// WriteJSON renders a TraceResult as structured JSON.
func WriteJSON(w io.Writer, tr *TraceResult) error {
	out := jsonResult{
		ControlID:   string(tr.ControlID),
		AssetID:     tr.AssetID.String(),
		Properties:  tr.Properties,
		Root:        groupToJSON(tr.Root),
		FinalResult: tr.FinalResult,
	}
	return jsonutil.WriteIndented(w, out)
}

func groupToJSON(g *GroupNode) jsonNode {
	var sc *int
	if g.ShortCircuitIndex >= 0 {
		v := g.ShortCircuitIndex
		sc = &v
	}
	n := jsonNode{
		Kind:         kindGroup,
		Logic:        g.Logic.String(),
		Result:       g.Result,
		ShortCircuit: sc,
		Reason:       g.Reason,
	}
	for _, child := range g.Children {
		n.Children = append(n.Children, nodeToJSON(child))
	}
	return n
}

func nodeToJSON(node Node) jsonNode { return node.toJSON() }

func (g *GroupNode) toJSON() jsonNode    { return groupToJSON(g) }
func (c *ClauseNode) toJSON() jsonNode   { return clauseToJSON(c) }
func (f *FieldRefNode) toJSON() jsonNode { return fieldRefToJSON(f) }
func (a *AnyMatchNode) toJSON() jsonNode { return anyMatchToJSON(a) }

func clauseToJSON(c *ClauseNode) jsonNode {
	idx := c.Index
	exists := c.FieldExists
	return jsonNode{
		Kind:           kindClause,
		Index:          &idx,
		Field:          c.Field,
		Op:             c.Op,
		Value:          c.Value,
		ResolvedValue:  c.ResolvedValue,
		FieldValue:     c.FieldValue,
		ValueFromParam: c.ValueFromParam,
		FieldExists:    &exists,
		Result:         c.Result,
		Explanation:    clauseExplanation(c),
	}
}

func fieldRefToJSON(f *FieldRefNode) jsonNode {
	idx := f.Index
	exists := f.FieldExists
	otherExists := f.OtherExists
	return jsonNode{
		Kind:        kindFieldRef,
		Index:       &idx,
		Field:       f.Field,
		Op:          f.Op,
		OtherField:  f.OtherField,
		FieldValue:  f.FieldValue,
		OtherValue:  f.OtherValue,
		FieldExists: &exists,
		OtherExists: &otherExists,
		Result:      f.Result,
		Explanation: fieldRefExplanation(f),
	}
}

func anyMatchToJSON(a *AnyMatchNode) jsonNode {
	idx := a.Index
	exists := a.FieldExists
	count := a.IdentityCount
	n := jsonNode{
		Kind:          kindAnyMatch,
		Index:         &idx,
		Field:         a.Field,
		FieldExists:   &exists,
		IdentityCount: &count,
		MatchedIndex:  a.MatchedIndex,
		MatchedID:     a.MatchedID,
		Result:        a.Result,
	}
	if a.NestedTrace != nil {
		nested := groupToJSON(a.NestedTrace)
		n.NestedTrace = &nested
	}
	return n
}
