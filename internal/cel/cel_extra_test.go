package cel

import (
	"bytes"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// literal
// ---------------------------------------------------------------------------

func TestLiteral(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"true bool", true, "true"},
		{"false bool", false, "false"},
		{"string true", "true", "true"},
		{"string false", "false", "false"},
		{"string normal", "hello", `"hello"`},
		{"float64 int", float64(42), "42"},
		{"float64 frac", float64(3.14), "3.14"},
		{"int", 7, "7"},
		{"int64", int64(100), "100"},
		{"string slice", []string{"a", "b"}, `["a", "b"]`},
		{"any slice", []any{"x", true}, `["x", true]`},
		{"nil", nil, "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := literal(tt.in)
			if got != tt.want {
				t.Errorf("literal(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// fieldAccess / hasField
// ---------------------------------------------------------------------------

func TestFieldAccess(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"properties.storage.kind", `properties["storage"]["kind"]`},
		{"params.min_days", `params["min_days"]`},
		{"bare_field", `properties["bare_field"]`},
	}
	for _, tt := range tests {
		got := fieldAccess(tt.path)
		if got != tt.want {
			t.Errorf("fieldAccess(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestHasField(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"properties.x", `"x" in properties`},
		{"bare", `"bare" in properties`},
	}
	for _, tt := range tests {
		got := hasField(tt.path)
		if got == "" {
			t.Errorf("hasField(%q) returned empty", tt.path)
		}
		_ = got // just verify no panic
	}
}

// ---------------------------------------------------------------------------
// scopedFieldAccess / scopedHasField
// ---------------------------------------------------------------------------

func TestScopedFieldAccess(t *testing.T) {
	got := scopedFieldAccess("type", "__id")
	if got != `__id["type"]` {
		t.Fatalf("got %q", got)
	}

	got = scopedFieldAccess("grants.has_wildcard", "__id")
	if got != `__id["grants"]["has_wildcard"]` {
		t.Fatalf("got %q", got)
	}

	// empty scope
	got = scopedFieldAccess("properties.x", "")
	if got != `properties["x"]` {
		t.Fatalf("got %q", got)
	}
}

func TestScopedHasField(t *testing.T) {
	got := scopedHasField("type", "__id")
	if got != `"type" in __id` {
		t.Fatalf("got %q", got)
	}

	got = scopedHasField("grants.has_wildcard", "__id")
	if got == "" {
		t.Fatal("expected non-empty")
	}

	// empty scope
	got = scopedHasField("properties.x", "")
	if got == "" {
		t.Fatal("expected non-empty")
	}
}

// ---------------------------------------------------------------------------
// normalizePath
// ---------------------------------------------------------------------------

func TestNormalizePath(t *testing.T) {
	if got := normalizePath("properties.x"); got != "properties.x" {
		t.Fatalf("got %q", got)
	}
	if got := normalizePath("params.y"); got != "params.y" {
		t.Fatalf("got %q", got)
	}
	if got := normalizePath("bare_field"); got != "properties.bare_field" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// PredicateToExpr (exported)
// ---------------------------------------------------------------------------

func TestPredicateToExpr_Empty(t *testing.T) {
	expr, err := PredicateToExpr(policy.UnsafePredicate{})
	if err != nil {
		t.Fatal(err)
	}
	if expr != "false" {
		t.Fatalf("empty predicate should produce 'false', got %q", expr)
	}
}

func TestPredicateToExpr_SimpleAny(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.x"), Op: predicate.OpEq, Value: policy.Bool(true)},
			{Field: predicate.NewFieldPath("properties.y"), Op: predicate.OpNe, Value: policy.Str("bad")},
		},
	}
	expr, err := PredicateToExpr(pred)
	if err != nil {
		t.Fatal(err)
	}
	if expr == "" || expr == "false" {
		t.Fatalf("expected non-trivial expression, got %q", expr)
	}
}

// ---------------------------------------------------------------------------
// Compile errors
// ---------------------------------------------------------------------------

func TestCompile_EmptyPredicate(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiler.Compile(policy.UnsafePredicate{})
	// empty predicate produces "false" which compiles fine
	if err != nil {
		t.Fatalf("empty predicate should compile: %v", err)
	}
}

func TestCompile_UnsupportedOperator(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.x"), Op: predicate.Operator("bogus")},
		},
	}
	_, err = compiler.Compile(pred)
	if err == nil {
		t.Fatal("expected error for unsupported operator")
	}
}

// ---------------------------------------------------------------------------
// Operators: gt, lt, gte, lte, in, list_empty, neq_field, not_in_field, not_subset_of_field, present
// ---------------------------------------------------------------------------

func TestCompile_ComparisonOperators(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	ops := []struct {
		op  predicate.Operator
		val any
	}{
		{predicate.OpGt, float64(5)},
		{predicate.OpLt, float64(10)},
		{predicate.OpGte, float64(5)},
		{predicate.OpLte, float64(10)},
		{predicate.OpIn, []any{"a", "b"}},
		{predicate.OpListEmpty, true},
		{predicate.OpPresent, true},
		{predicate.OpPresent, false},
		{predicate.OpMissing, false},
	}

	for _, tt := range ops {
		pred := policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.x"), Op: tt.op, Value: policy.NewOperand(tt.val)},
			},
		}
		cp, compileErr := compiler.Compile(pred)
		if compileErr != nil {
			t.Fatalf("op %s: compile error: %v", tt.op, compileErr)
		}
		if cp.Expression == "" {
			t.Fatalf("op %s: empty expression", tt.op)
		}
	}
}

func TestCompile_NeqFieldOperator(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.a"), Op: predicate.OpNeqField, Value: policy.Str("properties.b")},
		},
	}
	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cp.Expression == "" {
		t.Fatal("empty expression")
	}
}

func TestCompile_NotInFieldOperator(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.a"), Op: predicate.OpNotInField, Value: policy.Str("properties.b")},
		},
	}
	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cp.Expression == "" {
		t.Fatal("empty expression")
	}
}

func TestCompile_NotSubsetOfFieldOperator(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.a"), Op: predicate.OpNotSubsetOfField, Value: policy.Str("properties.b")},
		},
	}
	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cp.Expression == "" {
		t.Fatal("empty expression")
	}
}

// ---------------------------------------------------------------------------
// NewPredicateEval
// ---------------------------------------------------------------------------

func TestNewPredicateEval(t *testing.T) {
	eval, err := NewPredicateEval()
	if err != nil {
		t.Fatal(err)
	}
	ctl := policy.ControlDefinition{
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.x"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
	}
	a := asset.Asset{Properties: map[string]any{"x": true}}
	unsafe, err := eval(ctl, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !unsafe {
		t.Fatal("expected unsafe")
	}
}

// ---------------------------------------------------------------------------
// TraceResult
// ---------------------------------------------------------------------------

func TestTraceResultRenderText(t *testing.T) {
	tr := &TraceResult{
		ControlID:  kernel.ControlID("CTL.TEST.001"),
		AssetID:    asset.ID("bucket-a"),
		Expression: "true",
		Result:     true,
	}
	var buf bytes.Buffer
	if err := tr.RenderText(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty output")
	}
}

func TestTraceResultRenderJSON(t *testing.T) {
	tr := &TraceResult{
		ControlID:  kernel.ControlID("CTL.TEST.001"),
		AssetID:    asset.ID("bucket-a"),
		Expression: "true",
		Result:     true,
	}
	var buf bytes.Buffer
	if err := tr.RenderJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("empty output")
	}
}

func TestTraceResultRenderTextWithError(t *testing.T) {
	tr := &TraceResult{
		ControlID: kernel.ControlID("CTL.TEST.001"),
		AssetID:   asset.ID("bucket-a"),
		Error:     "some error",
	}
	var buf bytes.Buffer
	if err := tr.RenderText(&buf); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// BuildTrace
// ---------------------------------------------------------------------------

func TestBuildTrace_NilArgs(t *testing.T) {
	if BuildTrace(nil, nil, nil) != nil {
		t.Fatal("nil args should return nil")
	}
}

func TestBuildTrace_Simple(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID: kernel.ControlID("CTL.TEST.001"),
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.x"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
	}
	a := &asset.Asset{ID: asset.ID("bucket-a"), Properties: map[string]any{"x": true}}
	tr := BuildTrace(ctl, a, nil)
	if tr == nil {
		t.Fatal("expected non-nil trace")
	}
	if !tr.Result {
		t.Fatal("expected true result")
	}
	if tr.Expression == "" {
		t.Fatal("expected non-empty expression")
	}
}

// ---------------------------------------------------------------------------
// stringifyNamedTypes
// ---------------------------------------------------------------------------

func TestStringifyNamedTypes(t *testing.T) {
	type namedStr string
	m := map[string]any{
		"plain":  "hello",
		"named":  namedStr("world"),
		"nested": map[string]any{"inner": namedStr("val")},
		"list":   []any{namedStr("a"), "b"},
		"bool":   true,
		"nil":    nil,
	}
	result := stringifyNamedTypes(m)
	if result["named"] != "world" {
		t.Fatalf("named = %v (%T)", result["named"], result["named"])
	}
	nested := result["nested"].(map[string]any)
	if nested["inner"] != "val" {
		t.Fatalf("nested.inner = %v", nested["inner"])
	}
}

// ---------------------------------------------------------------------------
// parseNestedPredicate
// ---------------------------------------------------------------------------

func TestParseNestedPredicate_Nil(t *testing.T) {
	p, err := parseNestedPredicate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("expected nil for nil input")
	}
}

func TestParseNestedPredicate_BadType(t *testing.T) {
	_, err := parseNestedPredicate("not a map")
	if err == nil {
		t.Fatal("expected error for non-map input")
	}
}

func TestParseNestedPredicate_Valid(t *testing.T) {
	input := map[string]any{
		"any": []any{
			map[string]any{"field": "type", "op": "eq", "value": "test"},
		},
	}
	p, err := parseNestedPredicate(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Any) != 1 {
		t.Fatalf("expected 1 any rule, got %d", len(p.Any))
	}
}

func TestParseRuleList_BadType(t *testing.T) {
	_, err := parseRuleList("not a list")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRuleList_BadItem(t *testing.T) {
	_, err := parseRuleList([]any{"not a map"})
	if err == nil {
		t.Fatal("expected error")
	}
}
