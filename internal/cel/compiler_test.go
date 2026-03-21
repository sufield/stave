package cel

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

func TestCompile_SimpleAllPredicate(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
			{Field: predicate.NewFieldPath("properties.storage.versioning.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cp.Expression == "" {
		t.Fatal("expected non-empty expression")
	}
	t.Logf("expression: %s", cp.Expression)
}

func TestCompile_EvaluateMatching(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
			{Field: predicate.NewFieldPath("properties.storage.versioning.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}

	// Unsafe bucket: versioning disabled
	props := map[string]any{
		"storage": map[string]any{
			"kind": "bucket",
			"versioning": map[string]any{
				"enabled": false,
			},
		},
	}

	result, err := evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !result {
		t.Fatal("expected unsafe (true) for bucket with versioning disabled")
	}
}

func TestCompile_EvaluateNonMatching(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
			{Field: predicate.NewFieldPath("properties.storage.versioning.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}

	// Safe bucket: versioning enabled
	props := map[string]any{
		"storage": map[string]any{
			"kind": "bucket",
			"versioning": map[string]any{
				"enabled": true,
			},
		},
	}

	result, err := evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if result {
		t.Fatal("expected safe (false) for bucket with versioning enabled")
	}
}

func TestCompile_MissingField(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
			{Field: predicate.NewFieldPath("properties.storage.versioning.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}

	// Missing versioning field entirely
	props := map[string]any{
		"storage": map[string]any{
			"kind": "bucket",
		},
	}

	result, err := evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	// eq false on missing field should return false (Stave semantics)
	if result {
		t.Fatal("expected false for missing versioning field (eq false)")
	}
}

func TestCompile_MissingOperator(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.tags.public_list_intended"), Op: predicate.OpMissing, Value: policy.Bool(true)},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}

	// Field is absent
	props := map[string]any{}

	result, err := evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !result {
		t.Fatal("expected true for missing field with 'missing' operator")
	}
}

func TestCompile_NestedAnyAll(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	// all:
	//   - field: properties.storage.kind, op: eq, value: bucket
	//   - field: properties.storage.access.public_list, op: eq, value: true
	//   - any:
	//       - field: properties.storage.tags.intent, op: missing, value: true
	//       - field: properties.storage.tags.intent, op: ne, value: "true"
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
			{Field: predicate.NewFieldPath("properties.storage.access.public_list"), Op: predicate.OpEq, Value: policy.Bool(true)},
			{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.tags.intent"), Op: predicate.OpMissing, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.tags.intent"), Op: predicate.OpNe, Value: policy.Str("true")},
				},
			},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("expression: %s", cp.Expression)

	// Public list bucket without intent tag
	props := map[string]any{
		"storage": map[string]any{
			"kind": "bucket",
			"access": map[string]any{
				"public_list": true,
			},
		},
	}

	result, err := evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !result {
		t.Fatal("expected unsafe for public list bucket without intent tag")
	}
}

func TestCompile_ContainsOperator(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.name"), Op: predicate.OpContains, Value: policy.Str("public")},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}

	props := map[string]any{"name": "my-public-bucket"}
	result, err := evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !result {
		t.Fatal("expected true for string containing 'public'")
	}

	props = map[string]any{"name": "my-private-bucket"}
	result, err = evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if result {
		t.Fatal("expected false for string not containing 'public'")
	}
}

func TestCompile_CacheHit(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.x"), Op: predicate.OpEq, Value: policy.Bool(true)},
		},
	}

	cp1, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}
	cp2, err := compiler.Compile(pred)
	if err != nil {
		t.Fatal(err)
	}

	if cp1.Expression != cp2.Expression {
		t.Fatalf("expected same expression, got %q vs %q", cp1.Expression, cp2.Expression)
	}
}

func TestCompile_AnyMatch(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	// Build predicate matching the canonical CTL.S3.TENANT.ISOLATION.001:
	// all:
	//   - field: properties.storage.kind, op: eq, value: bucket
	//   - field: properties.storage.tags.tenant_mode, op: eq, value: shared
	//   - field: properties.storage.tags.tenant_prefix, op: present, value: true
	//   - field: identities, op: any_match, value:
	//       all:
	//         - field: type, op: eq, value: app_signer
	//         - field: id, op: contains, value: "appsigner:s3:"
	//         - any:
	//             - field: purpose, op: contains, value: "allow_traversal=true"
	//             - field: purpose, op: contains, value: "enforce_prefix=false"
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq, Value: policy.Str("bucket")},
			{Field: predicate.NewFieldPath("properties.storage.tags.tenant_mode"), Op: predicate.OpEq, Value: policy.Str("shared")},
			{Field: predicate.NewFieldPath("properties.storage.tags.tenant_prefix"), Op: predicate.OpPresent, Value: policy.Bool(true)},
			{
				Field: predicate.NewFieldPath("identities"),
				Op:    predicate.OpAnyMatch,
				Value: policy.NewOperand(map[string]any{
					"all": []any{
						map[string]any{"field": "type", "op": "eq", "value": "app_signer"},
						map[string]any{"field": "id", "op": "contains", "value": "appsigner:s3:"},
						map[string]any{
							"any": []any{
								map[string]any{"field": "purpose", "op": "contains", "value": "allow_traversal=true"},
								map[string]any{"field": "purpose", "op": "contains", "value": "enforce_prefix=false"},
							},
						},
					},
				}),
			},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("expression: %s", cp.Expression)

	// Unsafe: shared bucket with unsafe signer
	props := map[string]any{
		"storage": map[string]any{
			"kind": "bucket",
			"tags": map[string]any{
				"tenant_mode":   "shared",
				"tenant_prefix": "org-123/",
			},
		},
	}
	identities := []any{
		map[string]any{
			"id":      "appsigner:s3:uploads",
			"type":    "app_signer",
			"vendor":  "aws",
			"purpose": "enforce_prefix=false allow_traversal=false",
		},
	}

	result, err := evaluateWithParams(cp, props, nil, identities)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !result {
		t.Fatal("expected unsafe (true) for signer with enforce_prefix=false")
	}

	// Safe: shared bucket with safe signer
	identities = []any{
		map[string]any{
			"id":      "appsigner:s3:uploads",
			"type":    "app_signer",
			"vendor":  "aws",
			"purpose": "enforce_prefix=true allow_traversal=false",
		},
	}

	result, err = evaluateWithParams(cp, props, nil, identities)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if result {
		t.Fatal("expected safe (false) for signer with enforce_prefix=true")
	}

	// Safe: shared bucket with no identities
	result, err = evaluateWithParams(cp, props, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if result {
		t.Fatal("expected safe (false) for empty identities list")
	}

	// Safe: non-shared bucket (tenant_mode not "shared")
	props["storage"].(map[string]any)["tags"].(map[string]any)["tenant_mode"] = "single"
	result, err = evaluateWithParams(cp, props, nil, identities)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if result {
		t.Fatal("expected safe (false) for non-shared bucket")
	}
}
