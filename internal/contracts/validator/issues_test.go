package validator

import (
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

func TestIsUnknownFieldDiagnostic(t *testing.T) {
	cases := []struct {
		name string
		diag Diagnostic
		want bool
	}{
		{
			name: "typed additional properties",
			diag: Diagnostic{Kind: &kind.AdditionalProperties{Properties: []string{"foo"}}},
			want: true,
		},
		{
			name: "typed required",
			diag: Diagnostic{Kind: &kind.Required{Missing: []string{"bar"}}},
			want: false,
		},
		{
			name: "nil kind falls through",
			diag: Diagnostic{Message: "some violation"},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUnknownFieldDiagnostic(tc.diag); got != tc.want {
				t.Fatalf("IsUnknownFieldDiagnostic()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestDiagnosticsResult_FiltersUnknownInNonStrict(t *testing.T) {
	diags := []Diagnostic{
		{Path: "/a", Message: "additional properties 'x' not allowed", Kind: &kind.AdditionalProperties{Properties: []string{"x"}}},
		{Path: "/b", Message: "missing property 'y'", Kind: &kind.Required{Missing: []string{"y"}}},
	}
	nonStrict := DiagnosticsResult(diags, "Fix schema violations", false)
	if len(nonStrict.Issues) != 1 {
		t.Fatalf("non-strict issues=%d want 1", len(nonStrict.Issues))
	}
	strict := DiagnosticsResult(diags, "Fix schema violations", true)
	if len(strict.Issues) != 2 {
		t.Fatalf("strict issues=%d want 2", len(strict.Issues))
	}
}
