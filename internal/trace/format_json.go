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
	ActualValue    any                `json:"field_value,omitempty"`
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

// WriteJSON renders a Result as structured JSON.
func WriteJSON(w io.Writer, tr *Result) error {
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
	children := make([]jsonNode, len(g.Children))
	for i, child := range g.Children {
		children[i] = nodeToJSON(child)
	}
	return jsonNode{
		Kind:         kindGroup,
		Logic:        g.Logic.String(),
		Children:     children,
		Result:       g.Result,
		ShortCircuit: sc,
		Reason:       g.Reason,
	}
}

func nodeToJSON(node Node) jsonNode {
	switch n := node.(type) {
	case *GroupNode:
		return groupToJSON(n)
	case *ClauseNode:
		return clauseToJSON(n)
	case *FieldRefNode:
		return fieldRefToJSON(n)
	case *AnyMatchNode:
		return anyMatchToJSON(n)
	default:
		return jsonNode{}
	}
}

func clauseToJSON(c *ClauseNode) jsonNode {
	idx := c.Index
	exists := c.FieldExists
	return jsonNode{
		Kind:           kindClause,
		Index:          &idx,
		Field:          c.Field.String(),
		Op:             c.Op,
		Value:          c.Value,
		ResolvedValue:  c.ResolvedValue,
		ActualValue:    c.ActualValue,
		ValueFromParam: c.ValueFromParam.String(),
		FieldExists:    &exists,
		Result:         c.Result,
		Explanation:    c.Explain(),
	}
}

func fieldRefToJSON(f *FieldRefNode) jsonNode {
	idx := f.Index
	exists := f.FieldExists
	otherExists := f.OtherExists
	return jsonNode{
		Kind:        kindFieldRef,
		Index:       &idx,
		Field:       f.Field.String(),
		Op:          f.Op,
		OtherField:  f.OtherField.String(),
		ActualValue: f.ActualValue,
		OtherValue:  f.OtherValue,
		FieldExists: &exists,
		OtherExists: &otherExists,
		Result:      f.Result,
		Explanation: f.Explain(),
	}
}

func anyMatchToJSON(a *AnyMatchNode) jsonNode {
	idx := a.Index
	exists := a.FieldExists
	count := a.IdentityCount
	var mi *int
	if a.MatchedIndex >= 0 {
		v := a.MatchedIndex
		mi = &v
	}
	n := jsonNode{
		Kind:          kindAnyMatch,
		Index:         &idx,
		Field:         a.Field.String(),
		FieldExists:   &exists,
		IdentityCount: &count,
		MatchedIndex:  mi,
		MatchedID:     a.MatchedID.String(),
		Result:        a.Result,
	}
	if a.NestedTrace != nil {
		nested := groupToJSON(a.NestedTrace)
		n.NestedTrace = &nested
	}
	return n
}
