package explain

import (
	"context"
	"fmt"
	"testing"

	"github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// Mock ControlFinder
// ---------------------------------------------------------------------------

type mockFinder struct {
	ctl policy.ControlDefinition
	err error
}

func (m *mockFinder) FindByID(_ context.Context, _ string, _ kernel.ControlID) (policy.ControlDefinition, error) {
	return m.ctl, m.err
}

// ---------------------------------------------------------------------------
// Explainer.Run
// ---------------------------------------------------------------------------

func TestRun_EmptyControlID(t *testing.T) {
	e := &Explainer{Finder: &mockFinder{}}
	_, err := e.Run(context.Background(), ExplainInput{})
	if err == nil {
		t.Fatal("expected error for empty control ID")
	}
}

func TestRun_FinderError(t *testing.T) {
	e := &Explainer{Finder: &mockFinder{err: fmt.Errorf("not found")}}
	_, err := e.Run(context.Background(), ExplainInput{ControlID: "CTL.A.001", ControlsDir: "controls"})
	if err == nil {
		t.Fatal("expected error from finder")
	}
}

func TestRun_Success(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:          kernel.ControlID("CTL.A.001"),
		Name:        "Test Control",
		Description: "A test control",
		Type:        policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{
					Field: predicate.NewFieldPath("properties.public"),
					Op:    predicate.OpEq,
					Value: policy.Bool(true),
				},
			},
		},
	}
	e := &Explainer{Finder: &mockFinder{ctl: ctl}}
	result, err := e.Run(context.Background(), ExplainInput{ControlID: "CTL.A.001", ControlsDir: "controls"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ControlID != "CTL.A.001" {
		t.Fatalf("ControlID = %q", result.ControlID)
	}
	if result.Name != "Test Control" {
		t.Fatalf("Name = %q", result.Name)
	}
	if len(result.MatchedFields) != 1 || result.MatchedFields[0] != "properties.public" {
		t.Fatalf("MatchedFields = %v", result.MatchedFields)
	}
	if len(result.Rules) != 1 {
		t.Fatalf("Rules = %v", result.Rules)
	}
	if result.Rules[0].Op != predicate.OpEq {
		t.Fatalf("Rules[0].Op = %v", result.Rules[0].Op)
	}
}

// ---------------------------------------------------------------------------
// walkPredicate
// ---------------------------------------------------------------------------

func TestWalkPredicate_AnyAndAll(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.a"), Op: predicate.OpEq, Value: policy.Bool(true)},
		},
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.b"), Op: predicate.OpNe, Value: policy.Str("safe")},
		},
	}

	fields, rules := walkPredicate(pred, policy.ControlParams{})
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %v", len(fields), fields)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestWalkPredicate_NestedRules(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.nested"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
	}

	fields, rules := walkPredicate(pred, policy.ControlParams{})
	if len(fields) != 1 || fields[0] != "properties.nested" {
		t.Fatalf("expected [properties.nested], got %v", fields)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestWalkPredicate_Empty(t *testing.T) {
	fields, rules := walkPredicate(policy.UnsafePredicate{}, policy.ControlParams{})
	if len(fields) != 0 {
		t.Fatalf("expected 0 fields, got %d", len(fields))
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// sampleValue
// ---------------------------------------------------------------------------

func TestSampleValue_Missing(t *testing.T) {
	v := sampleValue(contracts.ExplainRule{Op: predicate.OpMissing})
	if v != nil {
		t.Fatalf("missing op should return nil, got %v", v)
	}
}

func TestSampleValue_WithValue(t *testing.T) {
	v := sampleValue(contracts.ExplainRule{Op: predicate.OpEq, Value: "hello"})
	if v != "hello" {
		t.Fatalf("should return provided value, got %v", v)
	}
}

func TestSampleValue_DefaultBool(t *testing.T) {
	v := sampleValue(contracts.ExplainRule{Op: predicate.OpEq})
	if v != false {
		t.Fatalf("eq without value should default to false, got %v", v)
	}
}

func TestSampleValue_DefaultString(t *testing.T) {
	v := sampleValue(contracts.ExplainRule{Op: predicate.OpContains})
	if v != "example" {
		t.Fatalf("contains without value should default to 'example', got %v", v)
	}
}

// ---------------------------------------------------------------------------
// setNested
// ---------------------------------------------------------------------------

func TestSetNested_Simple(t *testing.T) {
	root := map[string]any{}
	setNested(root, "key", "val")
	if root["key"] != "val" {
		t.Fatalf("expected root[key]=val, got %v", root)
	}
}

func TestSetNested_Deep(t *testing.T) {
	root := map[string]any{}
	setNested(root, "a.b.c", true)
	a, _ := root["a"].(map[string]any)
	b, _ := a["b"].(map[string]any)
	if b["c"] != true {
		t.Fatalf("expected a.b.c=true, got %v", root)
	}
}

func TestSetNested_Empty(t *testing.T) {
	root := map[string]any{}
	setNested(root, "", "val")
	if len(root) != 0 {
		t.Fatalf("empty path should be no-op, got %v", root)
	}
}

func TestSetNested_NilValue(t *testing.T) {
	root := map[string]any{}
	setNested(root, "key", nil)
	if _, ok := root["key"]; ok {
		t.Fatalf("nil value should be skipped, got %v", root)
	}
}

// ---------------------------------------------------------------------------
// buildMinimalObservation
// ---------------------------------------------------------------------------

func TestBuildMinimalObservation_HasRequiredKeys(t *testing.T) {
	fields := []string{"properties.public"}
	rules := []contracts.ExplainRule{
		{Path: "properties.public", Op: predicate.OpEq, Value: true},
	}

	obs := buildMinimalObservation(fields, rules)
	if obs["schema_version"] == nil {
		t.Fatal("missing schema_version")
	}
	if obs["captured_at"] == nil {
		t.Fatal("missing captured_at")
	}
	if obs["assets"] == nil {
		t.Fatal("missing assets")
	}

	assets, ok := obs["assets"].([]map[string]any)
	if !ok || len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %v", obs["assets"])
	}
	props, ok := assets[0]["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected properties map, got %v", assets[0]["properties"])
	}
	if props["public"] != true {
		t.Fatalf("expected properties.public=true, got %v", props)
	}
}

// ---------------------------------------------------------------------------
// resolveRuleValue
// ---------------------------------------------------------------------------

func TestResolveRuleValue_Literal(t *testing.T) {
	r := policy.PredicateRule{
		Field: predicate.NewFieldPath("properties.x"),
		Op:    predicate.OpEq,
		Value: policy.Bool(true),
	}
	val, comment := resolveRuleValue(r, policy.ControlParams{})
	if val != true {
		t.Fatalf("expected true, got %v", val)
	}
	if comment != "" {
		t.Fatalf("expected no comment, got %q", comment)
	}
}

func TestResolveRuleValue_FromParam(t *testing.T) {
	params := policy.ControlParams{}
	params.Set("threshold", "7d")

	r := policy.PredicateRule{
		Field:          predicate.NewFieldPath("properties.x"),
		Op:             predicate.OpEq,
		Value:          policy.Str("default"),
		ValueFromParam: predicate.ParamRef("threshold"),
	}
	val, comment := resolveRuleValue(r, params)
	if val != "7d" {
		t.Fatalf("expected '7d' from params, got %v", val)
	}
	if comment == "" {
		t.Fatal("expected comment for param-resolved value")
	}
}
