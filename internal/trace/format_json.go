package trace

import (
	"io"

	"github.com/sufield/stave/internal/domain/predicate"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// WriteJSON serializes a Result into structured, indented JSON.
func WriteJSON(w io.Writer, tr *Result) error {
	out := jsonResult{
		ControlID:   tr.ControlID.String(),
		AssetID:     tr.AssetID.String(),
		Properties:  tr.Properties,
		Root:        nodeToJSON(tr.Root),
		FinalResult: tr.FinalResult,
	}
	return jsonutil.WriteIndented(w, out)
}

// --- Wire Format Types ---

type nodeKind string

const (
	kindGroup    nodeKind = "group"
	kindClause   nodeKind = "clause"
	kindFieldRef nodeKind = "field_ref"
	kindAnyMatch nodeKind = "any_match"
)

type jsonResult struct {
	ControlID   string         `json:"control_id"`
	AssetID     string         `json:"asset_id"`
	Properties  map[string]any `json:"properties"`
	Root        jsonNode       `json:"root"`
	FinalResult bool           `json:"final_result"`
}

// jsonNode is a flat union type discriminated by "kind".
// Pointer fields support correct omitempty behavior.
type jsonNode struct {
	Kind   nodeKind `json:"kind"`
	Result bool     `json:"result"`

	// Group fields
	Logic        string     `json:"logic,omitempty"`
	Children     []jsonNode `json:"children,omitempty"`
	ShortCircuit *int       `json:"short_circuit,omitempty"`
	Reason       string     `json:"reason,omitempty"`

	// Clause fields
	Index          *int               `json:"index,omitempty"`
	Field          string             `json:"field,omitempty"`
	Op             predicate.Operator `json:"op,omitempty"`
	Value          any                `json:"value,omitempty"`
	ResolvedValue  any                `json:"resolved_value,omitempty"`
	ActualValue    any                `json:"field_value,omitempty"`
	ValueFromParam string             `json:"value_from_param,omitempty"`
	FieldExists    *bool              `json:"field_exists,omitempty"`
	Explanation    string             `json:"explanation,omitempty"`

	// FieldRef fields
	OtherField  string `json:"other_field,omitempty"`
	OtherValue  any    `json:"other_value,omitempty"`
	OtherExists *bool  `json:"other_exists,omitempty"`

	// AnyMatch fields
	IdentityCount *int      `json:"identity_count,omitempty"`
	MatchedIndex  *int      `json:"matched_index,omitempty"`
	MatchedID     string    `json:"matched_id,omitempty"`
	NestedTrace   *jsonNode `json:"nested_trace,omitempty"`
}

// --- Translation ---

func nodeToJSON(node Node) jsonNode {
	if node == nil {
		return jsonNode{}
	}

	switch n := node.(type) {
	case *GroupNode:
		children := make([]jsonNode, len(n.Children))
		for i, child := range n.Children {
			children[i] = nodeToJSON(child)
		}
		res := jsonNode{
			Kind:     kindGroup,
			Logic:    n.Logic.String(),
			Children: children,
			Result:   n.Result,
			Reason:   n.Reason,
		}
		if n.ShortCircuitIndex >= 0 {
			res.ShortCircuit = new(n.ShortCircuitIndex)
		}
		return res

	case *ClauseNode:
		return jsonNode{
			Kind:           kindClause,
			Result:         n.Result,
			Index:          new(n.Index),
			Field:          n.Field.String(),
			Op:             n.Op,
			Value:          n.Value,
			ResolvedValue:  n.ResolvedValue,
			ActualValue:    n.ActualValue,
			ValueFromParam: n.ValueFromParam.String(),
			FieldExists:    new(n.FieldExists),
			Explanation:    n.Explain(),
		}

	case *FieldRefNode:
		return jsonNode{
			Kind:        kindFieldRef,
			Result:      n.Result,
			Index:       new(n.Index),
			Field:       n.Field.String(),
			Op:          n.Op,
			OtherField:  n.OtherField.String(),
			ActualValue: n.ActualValue,
			OtherValue:  n.OtherValue,
			FieldExists: new(n.FieldExists),
			OtherExists: new(n.OtherExists),
			Explanation: n.Explain(),
		}

	case *AnyMatchNode:
		res := jsonNode{
			Kind:          kindAnyMatch,
			Result:        n.Result,
			Index:         new(n.Index),
			Field:         n.Field.String(),
			FieldExists:   new(n.FieldExists),
			IdentityCount: new(n.IdentityCount),
			MatchedID:     n.MatchedID.String(),
		}
		if n.MatchedIndex >= 0 {
			res.MatchedIndex = new(n.MatchedIndex)
		}
		if n.NestedTrace != nil {
			nested := nodeToJSON(n.NestedTrace)
			res.NestedTrace = &nested
		}
		return res

	default:
		return jsonNode{}
	}
}
