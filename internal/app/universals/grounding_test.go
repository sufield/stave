package universals

import (
	"strings"
	"testing"
	"time"
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

func TestVerdict_DomainMethods(t *testing.T) {
	if !VerdictHolds.IsHolds() {
		t.Error("VerdictHolds.IsHolds(): got false, want true")
	}
	if VerdictHolds.IsViolated() || VerdictHolds.IsError() || VerdictHolds.IsUnknown() {
		t.Error("VerdictHolds returned true for other states")
	}

	if !VerdictViolated.IsViolated() {
		t.Error("VerdictViolated.IsViolated(): got false, want true")
	}
	if !VerdictError.IsError() {
		t.Error("VerdictError.IsError(): got false, want true")
	}
	if !VerdictUnknown.IsUnknown() {
		t.Error("VerdictUnknown.IsUnknown(): got false, want true")
	}
}

func TestSolveTimeMs_DomainMethods(t *testing.T) {
	st := SolveTimeMs(1500)
	if st.Int64() != 1500 {
		t.Errorf("Int64: got %d, want 1500", st.Int64())
	}
	if st.Duration() != 1500*time.Millisecond {
		t.Errorf("Duration: got %v, want 1.5s", st.Duration())
	}
	if st.Seconds() != 1.5 {
		t.Errorf("Seconds: got %f, want 1.5", st.Seconds())
	}
	if !st.IsSlow(time.Second) {
		t.Error("IsSlow(1s): got false, want true")
	}
	if st.IsSlow(2 * time.Second) {
		t.Error("IsSlow(2s): got true, want false")
	}
}

func TestViolations_DomainMethods(t *testing.T) {
	viols := Violations{
		{Constant: "c_bucket1", Predicate: "encrypted", Value: false},
		{Constant: "c_bucket2", Predicate: "encrypted", Value: false},
		{Constant: "c_fn1", Predicate: "requires_auth", Value: false},
	}

	if viols.Len() != 3 {
		t.Errorf("Len: got %d, want 3", viols.Len())
	}

	enc := viols.ByPredicate("encrypted")
	if enc.Len() != 2 {
		t.Errorf("ByPredicate encrypted: got %d, want 2", enc.Len())
	}

	fn := viols.ByConstant("c_fn1")
	if fn.Len() != 1 || fn[0].Predicate != "requires_auth" {
		t.Errorf("ByConstant c_fn1: got %v", fn)
	}

	preds := viols.Predicates()
	if len(preds) != 2 || preds[0] != "encrypted" || preds[1] != "requires_auth" {
		t.Errorf("Predicates: got %v, want [encrypted, requires_auth]", preds)
	}
}

func TestResults_DomainMethods(t *testing.T) {
	res := Results{
		{
			ID:          "U26",
			Name:        "Service-level logging enabled",
			Verdict:     VerdictHolds,
			Holds:       true,
			SolveTimeMs: 100,
		},
		{
			ID:          "U27",
			Name:        "Endpoint authentication required",
			Verdict:     VerdictViolated,
			Holds:       false,
			SolveTimeMs: 250,
			Violations: Violations{
				{Constant: "c_fn1", Predicate: "requires_auth", Value: false},
			},
		},
		{
			ID:          "U28",
			Name:        "Deletion protection enabled",
			Verdict:     VerdictError,
			Holds:       false,
			Error:       "z3 timeout",
			SolveTimeMs: 500,
		},
	}

	if res.Len() != 3 {
		t.Errorf("Len: got %d, want 3", res.Len())
	}

	holding := res.Holding()
	if holding.Len() != 1 || holding[0].ID != "U26" {
		t.Errorf("Holding: got %v", holding)
	}

	violated := res.Violated()
	if violated.Len() != 1 || violated[0].ID != "U27" {
		t.Errorf("Violated: got %v", violated)
	}

	errored := res.Errored()
	if errored.Len() != 1 || errored[0].ID != "U28" {
		t.Errorf("Errored: got %v", errored)
	}

	u27, found := res.ByID("U27")
	if !found || u27.Name != "Endpoint authentication required" {
		t.Errorf("ByID U27: got (%v, %v)", u27, found)
	}

	_, notFound := res.ByID("U99")
	if notFound {
		t.Error("ByID U99: got true, want false")
	}

	totalTime := res.TotalSolveTime()
	if totalTime != 850*time.Millisecond {
		t.Errorf("TotalSolveTime: got %v, want 850ms", totalTime)
	}
}
