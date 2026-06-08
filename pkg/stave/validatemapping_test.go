package stave

import (
	"bytes"
	"strings"
	"testing"
)

// These exercise the validate-mapping helpers + renderers that moved here
// from cmd/validatemapping. End-to-end coverage that loads catalogs from
// disk lives in the txtar suite.

func TestMappingStructuralFindings_OK(t *testing.T) {
	m := mappingDoc{
		AssetType:     "aws_s3_bucket",
		AssetIDColumn: "arn",
		Operations: []mappingOperation{
			{Kind: "field", Path: "properties.storage.kind", Column: "name"},
			{Kind: "static", Path: "properties.storage.foo", Value: "bar"},
			{Kind: "extract", Path: "properties.x.y", Column: "config", JSONPath: "Rules.0.X"},
			{Kind: "computed", Path: "properties.derived", Op: "all", Inputs: []string{"properties.a"}},
		},
	}
	if got := mappingStructuralFindings(m); len(got) != 0 {
		t.Fatalf("expected no findings, got %d: %+v", len(got), got)
	}
}

func TestMappingStructuralFindings_DetectsAllErrors(t *testing.T) {
	m := mappingDoc{
		AssetType:     "",
		AssetIDColumn: "",
		Operations: []mappingOperation{
			{Kind: "wibble", Path: "properties.x"},
			{Kind: "field", Path: ""},
			{Kind: "field", Path: "p.q"},
			{Kind: "static", Path: "p.q"},
			{Kind: "extract", Path: "p.q", Column: ""},
			{Kind: "computed", Path: "p.q", Op: "maybe"},
		},
	}
	got := mappingStructuralFindings(m)
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

func TestMappingStructuralFindings_OperationsRequired(t *testing.T) {
	m := mappingDoc{AssetType: "aws_s3_bucket", AssetIDColumn: "arn"}
	got := mappingStructuralFindings(m)
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
		{"storage.kind", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := pathDeclaredInSchema(schema, tc.path); got != tc.want {
			t.Errorf("pathDeclaredInSchema(%q): got %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestMappingOverallStatus_StructuralErrorAlwaysInvalid(t *testing.T) {
	r := mappingReport{Structural: []mappingFinding{{Severity: "error", Message: "boom"}}}
	if mappingOverallStatus(r, false) != "INVALID" {
		t.Fatal("structural error must yield INVALID regardless of strict mode")
	}
}

func TestMappingOverallStatus_StrictPromotesSchemaWarnings(t *testing.T) {
	r := mappingReport{Schema: []mappingFinding{{Severity: "warning", Message: "path unknown"}}}
	if mappingOverallStatus(r, false) != "VALID" {
		t.Error("schema warning must be VALID by default")
	}
	if mappingOverallStatus(r, true) != "INVALID" {
		t.Error("schema warning must be INVALID under --strict")
	}
}

func TestMappingOverallStatus_StrictPromotesCoverageGap(t *testing.T) {
	r := mappingReport{Coverage: mappingCoverage{CatalogPaths: 10, Populated: 3}}
	if mappingOverallStatus(r, false) != "VALID" {
		t.Error("partial coverage must be VALID by default")
	}
	if mappingOverallStatus(r, true) != "INVALID" {
		t.Error("partial coverage must be INVALID under --strict")
	}
}

func TestRenderMappingReport_NonEmpty(t *testing.T) {
	rep := mappingReport{
		File:          "fixtures/example.yaml",
		AssetType:     "aws_s3_bucket",
		OverallStatus: "VALID",
	}
	for _, format := range []string{"json", "text", ""} {
		out, err := renderMappingReport(rep, format)
		if err != nil {
			t.Fatalf("renderMappingReport(%q): %v", format, err)
		}
		if !bytes.Contains(out, []byte("aws_s3_bucket")) {
			t.Errorf("renderMappingReport(%q): missing asset type in output", format)
		}
	}
}
