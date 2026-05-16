package validatemapping

import (
	"strings"
	"testing"
)

func TestStructuralFindings_OK(t *testing.T) {
	m := mapping{
		AssetType:     "aws_s3_bucket",
		AssetIDColumn: "arn",
		Operations: []operation{
			{Kind: "field", Path: "properties.storage.kind", Column: "name"},
			{Kind: "static", Path: "properties.storage.foo", Value: "bar"},
			{Kind: "extract", Path: "properties.x.y", Column: "config", JSONPath: "Rules.0.X"},
			{Kind: "computed", Path: "properties.derived", Op: "all", Inputs: []string{"properties.a"}},
		},
	}
	got := structuralFindings(m)
	if len(got) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(got), got)
	}
}

func TestStructuralFindings_DetectsAllErrors(t *testing.T) {
	// Each operation deliberately omits one required subfield for its
	// kind. The test pins the exact set of error messages so a future
	// edit to structuralFindings has to update this list — keeping the
	// authored contract aligned with what the code enforces.
	m := mapping{
		AssetType:     "", // missing
		AssetIDColumn: "", // missing
		Operations: []operation{
			{Kind: "wibble", Path: "properties.x"},       // unknown kind
			{Kind: "field", Path: ""},                    // missing path
			{Kind: "field", Path: "p.q"},                 // missing column
			{Kind: "static", Path: "p.q"},                // missing value
			{Kind: "extract", Path: "p.q", Column: ""},   // missing column + json_path
			{Kind: "computed", Path: "p.q", Op: "maybe"}, // bad op, no inputs
		},
	}
	got := structuralFindings(m)
	// The contract is "report every issue at once" — a field op missing
	// BOTH path and column yields two findings, not one. The agent
	// fixes everything in a single pass rather than chasing serial
	// errors. Keep the want list in declaration order matching how
	// structuralFindings walks the mapping.
	want := []string{
		"missing required field: asset_type",
		"missing required field: asset_id_column",
		`unknown kind "wibble" (want field | static | extract | computed)`,
		"missing path",
		"field operation requires column",
		"field operation requires column",
		"static operation requires value",
		"extract operation requires column",
		"extract operation requires json_path",
		`computed operation requires op: any | all (got "maybe")`,
		"computed operation requires non-empty inputs",
	}
	if len(got) != len(want) {
		t.Fatalf("finding count: want %d, got %d\n%+v", len(want), len(got), got)
	}
	for i, w := range want {
		if !strings.Contains(got[i].Message, w) {
			t.Errorf("finding %d: want %q, got %q", i, w, got[i].Message)
		}
	}
}

func TestStructuralFindings_OperationsRequired(t *testing.T) {
	m := mapping{
		AssetType:     "aws_s3_bucket",
		AssetIDColumn: "arn",
		// operations omitted
	}
	got := structuralFindings(m)
	found := false
	for _, f := range got {
		if strings.Contains(f.Message, "operations (must be non-empty)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected operations-required finding, got %+v", got)
	}
}

func TestPathDeclaredInSchema(t *testing.T) {
	// Minimal schema with nested properties tree.
	schema := map[string]any{
		"properties": map[string]any{
			"storage": map[string]any{
				"properties": map[string]any{
					"kind": map[string]any{"type": "string"},
					"encryption": map[string]any{
						"properties": map[string]any{
							"algorithm": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	}
	cases := []struct {
		path string
		want bool
	}{
		{"properties.storage.kind", true},
		{"properties.storage.encryption.algorithm", true},
		{"properties.storage.banana", false},
		{"properties.unknown.kind", false},
		// Paths without the "properties." prefix don't match the
		// authored mapping convention and should be rejected.
		{"storage.kind", false},
		{"", false},
	}
	for _, tc := range cases {
		got := pathDeclaredInSchema(schema, tc.path)
		if got != tc.want {
			t.Errorf("pathDeclaredInSchema(%q): got %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestOverall_StructuralErrorAlwaysInvalid(t *testing.T) {
	r := report{
		Structural: []finding{{Severity: "error", Message: "boom"}},
	}
	if overall(r, false) != "INVALID" {
		t.Fatal("structural error must yield INVALID regardless of strict mode")
	}
}

func TestOverall_StrictPromotesSchemaWarnings(t *testing.T) {
	r := report{
		Schema: []finding{{Severity: "warning", Message: "path unknown"}},
	}
	if overall(r, false) != "VALID" {
		t.Error("schema warning must be VALID by default")
	}
	if overall(r, true) != "INVALID" {
		t.Error("schema warning must be INVALID under --strict")
	}
}

func TestOverall_StrictPromotesCoverageGap(t *testing.T) {
	r := report{
		Coverage: coverage{CatalogPaths: 10, Populated: 3},
	}
	if overall(r, false) != "VALID" {
		t.Error("partial coverage must be VALID by default")
	}
	if overall(r, true) != "INVALID" {
		t.Error("partial coverage must be INVALID under --strict")
	}
}
