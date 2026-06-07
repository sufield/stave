package cmd

import (
	"bytes"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestNewSchemasRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   SchemasRenderer
	}{
		{appcontracts.FormatJSON, schemasJSONRenderer{}},
		{appcontracts.FormatText, schemasTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format.String(), func(t *testing.T) {
			r, err := NewSchemasRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewSchemasRenderer(%q) error: %v", tc.format, err)
			}
			if r == nil {
				t.Fatalf("NewSchemasRenderer(%q) returned nil renderer", tc.format)
			}
			gotType := typeName(r)
			wantType := typeName(tc.want)
			if gotType != wantType {
				t.Errorf("NewSchemasRenderer(%q) = %s, want %s", tc.format, gotType, wantType)
			}
		})
	}
}

func TestNewSchemasRenderer_UnknownFormat(t *testing.T) {
	r, err := NewSchemasRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatal("NewSchemasRenderer(bogus) expected error, got nil")
	}
	if r != nil {
		t.Errorf("NewSchemasRenderer(bogus) expected nil renderer, got %T", r)
	}
}

func TestSchemasRenderers_Smoke(t *testing.T) {
	out := schemasOutput{
		Data:          []schemaEntry{{"control", "ctrl.v1"}},
		Diagnostic:    []schemaEntry{{"diagnose", "diagnose.v1"}},
		CommandOutput: []schemaEntry{{"validate", "validate.v0.1"}},
		Artifact:      []schemaEntry{{"bug_report", "bug-report.v0.1"}},
	}
	for _, format := range []appcontracts.OutputFormat{appcontracts.FormatJSON, appcontracts.FormatText} {
		t.Run(format.String(), func(t *testing.T) {
			r, err := NewSchemasRenderer(format)
			if err != nil {
				t.Fatalf("NewSchemasRenderer(%q) error: %v", format, err)
			}
			var buf bytes.Buffer
			if err := r.Render(&buf, out); err != nil {
				t.Fatalf("Render(%q) error: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render(%q) produced empty output", format)
			}
		})
	}
}

// typeName returns the concrete dynamic type name for renderer identity
// comparison in the known-formats table.
func typeName(r SchemasRenderer) string {
	switch r.(type) {
	case schemasJSONRenderer:
		return "schemasJSONRenderer"
	case schemasTextRenderer:
		return "schemasTextRenderer"
	default:
		return "unknown"
	}
}
