package universals

import (
	"strings"
	"testing"
)

func TestResolvePredicate(t *testing.T) {
	props := map[string]any{
		"storage": map[string]any{
			"logging": map[string]any{
				"enabled": true,
			},
		},
		"compute": map[string]any{
			"function_url": map[string]any{
				"auth_type_none": true,
			},
		},
	}

	tests := []struct {
		name string
		val  any
		want bool
	}{
		{"constant true", true, true},
		{"constant false", false, false},
		{"path present true", ".storage.logging.enabled", true},
		{"path missing", ".storage.encryption.enabled", false},
		{"negated path true", "!.compute.function_url.auth_type_none", false},
		{"negated path missing", "!.storage.encryption.enabled", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvePredicate(tt.val, props)
			if got != tt.want {
				t.Errorf("resolvePredicate(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestGroundAssets(t *testing.T) {
	ug := UniversalGrounding{
		Sort:       "Resource",
		Predicates: []string{"generates_security_events", "logging_enabled"},
		Groundings: map[string]AssetTypeGrounding{
			"aws_s3_bucket": {
				"generates_security_events": true,
				"logging_enabled":           ".storage.logging.enabled",
			},
		},
	}

	assets := []asset{
		{ID: "bucket-1", Type: "aws_s3_bucket", Properties: map[string]any{
			"storage": map[string]any{"logging": map[string]any{"enabled": false}},
		}},
		{ID: "role-1", Type: "aws_iam_role", Properties: map[string]any{}},
	}

	gs := GroundAssets(assets, ug)
	if len(gs) != 1 {
		t.Fatalf("got %d grounded, want 1", len(gs))
	}
	if gs[0].preds["generates_security_events"] != true {
		t.Error("generates_security_events should be true")
	}
	if gs[0].preds["logging_enabled"] != false {
		t.Error("logging_enabled should be false")
	}
}

func TestGroundAssetsWithWhen(t *testing.T) {
	ug := UniversalGrounding{
		Sort:       "Endpoint",
		Predicates: []string{"accepts_requests", "requires_auth"},
		Groundings: map[string]AssetTypeGrounding{
			"aws_lambda_function": {
				"when":             ".compute.function_url",
				"accepts_requests": true,
				"requires_auth":    "!.compute.function_url.auth_type_none",
			},
		},
	}

	t.Run("with function_url", func(t *testing.T) {
		assets := []asset{{ID: "fn-1", Type: "aws_lambda_function", Properties: map[string]any{
			"compute": map[string]any{
				"function_url": map[string]any{"auth_type_none": true},
			},
		}}}
		gs := GroundAssets(assets, ug)
		if len(gs) != 1 {
			t.Fatalf("got %d grounded, want 1", len(gs))
		}
		if gs[0].preds["requires_auth"] != false {
			t.Error("requires_auth should be false (auth_type_none=true)")
		}
	})

	t.Run("without function_url", func(t *testing.T) {
		assets := []asset{{ID: "fn-2", Type: "aws_lambda_function", Properties: map[string]any{
			"compute": map[string]any{"runtime": "go1.x"},
		}}}
		gs := GroundAssets(assets, ug)
		if len(gs) != 0 {
			t.Fatalf("got %d grounded, want 0 (when condition not met)", len(gs))
		}
	})
}

func TestGenerateGroundingEmpty(t *testing.T) {
	out := GenerateGrounding("Resource", []string{"stores_data"}, nil)
	if !strings.Contains(out, "forall") {
		t.Error("empty grounding should close universe with forall")
	}
}

func TestGenerateGroundingSingle(t *testing.T) {
	gs := []grounded{{name: "c_bucket", preds: map[string]bool{
		"stores_data": true,
		"encrypted":   false,
	}}}
	out := GenerateGrounding("Resource", []string{"stores_data", "encrypted"}, gs)
	if !strings.Contains(out, "(declare-const c_bucket Resource)") {
		t.Error("should declare constant")
	}
	if !strings.Contains(out, "(assert (stores_data c_bucket))") {
		t.Error("should assert true predicate")
	}
	if !strings.Contains(out, "(assert (not (encrypted c_bucket)))") {
		t.Error("should assert negated false predicate")
	}
}
