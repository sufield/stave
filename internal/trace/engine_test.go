package trace

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/domain/asset"

	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

func TestTracePredicate_AnyAllSemantics(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: "properties.flag", Op: predicate.OpEq, Value: true},
		},
		All: []policy.PredicateRule{
			{Field: "properties.ready", Op: predicate.OpEq, Value: true},
		},
	}

	tests := []struct {
		name       string
		properties map[string]any
		wantResult bool
	}{
		{name: "any true short-circuits to match", properties: map[string]any{"flag": true, "ready": false}, wantResult: true},
		{name: "any false and all true still matches", properties: map[string]any{"flag": false, "ready": true}, wantResult: true},
		{name: "any false and all false does not match", properties: map[string]any{"flag": false, "ready": false}, wantResult: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := TracePredicate(pred, policy.EvalContext{Properties: tt.properties})
			if root.Logic != LogicAnyAndAll {
				t.Fatalf("logic = %v, want LogicAnyAndAll", root.Logic)
			}
			if len(root.Children) != 2 {
				t.Fatalf("children = %d, want 2", len(root.Children))
			}
			if root.Result != tt.wantResult {
				t.Fatalf("result = %v, want %v", root.Result, tt.wantResult)
			}
		})
	}
}

func TestTracePredicate_ValueFromParamMissing(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: "properties.enabled", Op: predicate.OpEq, ValueFromParam: "desired"},
		},
	}
	root := TracePredicate(pred, policy.EvalContext{
		Properties: map[string]any{"enabled": true},
		Params:     nil,
	})

	if root.Result {
		t.Fatal("expected no match when value_from_param is missing")
	}
	if len(root.Children) != 1 {
		t.Fatalf("children = %d, want 1", len(root.Children))
	}
	clause, ok := root.Children[0].(*ClauseNode)
	if !ok {
		t.Fatalf("child type = %T, want *ClauseNode", root.Children[0])
	}
	if clause.Result {
		t.Fatal("expected clause result=false")
	}
	if clause.ValueFromParam != "desired" {
		t.Fatalf("value_from_param = %q, want %q", clause.ValueFromParam, "desired")
	}
	if clause.ResolvedValue != nil {
		t.Fatalf("resolved_value = %v, want nil (param not found)", clause.ResolvedValue)
	}
}

func TestTracePredicate_AnyMatchUsesResolvedParamAndCapturesMatch(t *testing.T) {
	receivedCompare := false
	testParser := func(v any) (*policy.UnsafePredicate, error) {
		if _, ok := v.(map[string]any); ok {
			receivedCompare = true
		}
		return &policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: "owner", Op: predicate.OpEq, Value: "alice"},
			},
		}, nil
	}

	ownerBob := "bob"
	ownerAlice := "alice"
	ctx := policy.EvalContext{
		Identities: []asset.CloudIdentity{
			{ID: "id-1", Properties: map[string]any{"owner": ownerBob}},
			{ID: "id-2", Properties: map[string]any{"owner": ownerAlice}},
		},
		Params: map[string]any{
			"nested": map[string]any{"any": []any{}},
		},
		PredicateParser: testParser,
	}
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: "identities", Op: predicate.OpAnyMatch, ValueFromParam: "nested"},
		},
	}

	root := TracePredicate(pred, ctx)
	if !root.Result {
		t.Fatal("expected predicate match")
	}
	if !receivedCompare {
		t.Fatal("expected nested parser to receive compare value resolved from params")
	}

	node, ok := root.Children[0].(*AnyMatchNode)
	if !ok {
		t.Fatalf("child type = %T, want *AnyMatchNode", root.Children[0])
	}
	if !node.Result {
		t.Fatal("expected any_match result=true")
	}
	if node.MatchedIndex == nil || *node.MatchedIndex != 1 {
		t.Fatalf("matched_index = %v, want 1", node.MatchedIndex)
	}
	if node.MatchedID != "id-2" {
		t.Fatalf("matched_id = %q, want id-2", node.MatchedID)
	}
	if node.NestedTrace == nil || !node.NestedTrace.Result {
		t.Fatal("expected nested trace result=true")
	}
}

func TestWriteText_PrintsTraceSections(t *testing.T) {
	root := &GroupNode{
		Logic:             LogicAny,
		ShortCircuitIndex: 0,
		Result:            true,
		Children: []Node{
			&ClauseNode{
				Index:         0,
				Field:         "properties.flag",
				Op:            predicate.OpEq,
				Value:         true,
				ResolvedValue: true,
				FieldValue:    true,
				FieldExists:   true,
				Result:        true,
			},
			&ClauseNode{
				Index:         1,
				Field:         "properties.ready",
				Op:            predicate.OpEq,
				Value:         true,
				ResolvedValue: true,
				FieldValue:    false,
				FieldExists:   true,
				Result:        false,
			},
		},
		Reason: "Clause 1 matched in any → MATCH",
	}

	tr := &TraceResult{
		ControlID: "CTL.TEST.001",
		AssetID:   "res:test",
		Properties: map[string]any{
			"flag":  true,
			"ready": false,
		},
		Root:        root,
		FinalResult: true,
	}

	var buf bytes.Buffer
	if err := WriteText(&buf, tr); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	out := buf.String()

	checks := []string{
		"Tracing CTL.TEST.001 against asset res:test",
		"Asset Properties:",
		"properties.flag: true",
		"Predicate: any",
		"... (short-circuited)",
		"Final Result: PREDICATE MATCHED",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Fatalf("output missing %q\n\n%s", check, out)
		}
	}
}

func TestWriteJSON_EncodesAllNodeKinds(t *testing.T) {
	anyMatch := &AnyMatchNode{
		Index:         2,
		Field:         "identities",
		FieldExists:   true,
		IdentityCount: 1,
		Result:        true,
		MatchedID:     "id-1",
		NestedTrace: &GroupNode{
			Logic:             LogicAny,
			ShortCircuitIndex: -1,
			Result:            true,
			Children: []Node{
				&ClauseNode{
					Index:         0,
					Field:         "owner",
					Op:            predicate.OpEq,
					Value:         "alice",
					ResolvedValue: "alice",
					FieldValue:    "alice",
					FieldExists:   true,
					Result:        true,
				},
			},
			Reason: "Clause 1 matched in any → MATCH",
		},
	}
	matchIdx := 0
	anyMatch.MatchedIndex = &matchIdx

	tr := &TraceResult{
		ControlID:  "CTL.TEST.002",
		AssetID:    "res:test",
		Properties: map[string]any{"x": 1},
		Root: &GroupNode{
			Logic:             LogicAll,
			ShortCircuitIndex: -1,
			Result:            false,
			Children: []Node{
				&ClauseNode{
					Index:         0,
					Field:         "properties.x",
					Op:            predicate.OpEq,
					Value:         1,
					ResolvedValue: 1,
					FieldValue:    1,
					FieldExists:   true,
					Result:        true,
				},
				&FieldRefNode{
					Index:       1,
					Field:       "properties.a",
					Op:          predicate.OpNeqField,
					OtherField:  "properties.b",
					FieldValue:  "a",
					OtherValue:  "b",
					FieldExists: true,
					OtherExists: true,
					Result:      true,
				},
				anyMatch,
			},
			Reason: "Clause 3 failed in all → NO MATCH",
		},
		FinalResult: false,
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, tr); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	var decoded struct {
		Root struct {
			Children []struct {
				Kind string `json:"kind"`
			} `json:"children"`
		} `json:"root"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(decoded.Root.Children) != 3 {
		t.Fatalf("children = %d, want 3", len(decoded.Root.Children))
	}

	kinds := []string{
		decoded.Root.Children[0].Kind,
		decoded.Root.Children[1].Kind,
		decoded.Root.Children[2].Kind,
	}
	want := []string{"clause", "field_ref", "any_match"}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("child[%d].kind = %q, want %q", i, kinds[i], want[i])
		}
	}
}
