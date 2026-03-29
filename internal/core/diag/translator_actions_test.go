package diag

import "testing"

func TestNewTranslator_EmptyDefaultCode(t *testing.T) {
	tr := NewTranslator("")
	if tr.defaultCode != CodeSchemaViolation {
		t.Fatalf("empty default code should fallback to %q, got %q", CodeSchemaViolation, tr.defaultCode)
	}
}

func TestNewTranslator_WhitespaceDefaultCode(t *testing.T) {
	tr := NewTranslator("  ")
	if tr.defaultCode != CodeSchemaViolation {
		t.Fatalf("whitespace default code should fallback to %q, got %q", CodeSchemaViolation, tr.defaultCode)
	}
}

func TestNewTranslator_CustomCode(t *testing.T) {
	tr := NewTranslator(CodeControlLoadFailed)
	if tr.defaultCode != CodeControlLoadFailed {
		t.Fatalf("defaultCode=%q, want %q", tr.defaultCode, CodeControlLoadFailed)
	}
}

func TestTranslator_MapCode_KnownCodes(t *testing.T) {
	tr := NewTranslator(CodeControlLoadFailed)
	knownCodes := []string{"required", "type", "enum", "additional_properties"}
	for _, code := range knownCodes {
		got := tr.mapCode(code)
		if got != CodeSchemaViolation {
			t.Fatalf("mapCode(%q)=%q, want %q", code, got, CodeSchemaViolation)
		}
	}
}

func TestTranslator_MapCode_UnknownCode(t *testing.T) {
	tr := NewTranslator(CodeControlLoadFailed)
	got := tr.mapCode("something_else")
	if got != CodeControlLoadFailed {
		t.Fatalf("mapCode(unknown)=%q, want %q", got, CodeControlLoadFailed)
	}
}

func TestTranslator_DeriveAction_AllKnownCodes(t *testing.T) {
	tr := NewTranslator(CodeSchemaViolation)

	tests := []struct {
		code  string
		field string
		want  string
	}{
		{"required", "version", "Add the missing field: version"},
		{"required", "", "Add the missing required field."},
		{"type", "name", "Set name to a value of the expected type."},
		{"type", "", "Use a value of the expected type."},
		{"enum", "status", "Set status to one of the allowed values."},
		{"enum", "", "Use one of the allowed values."},
		{"additional_properties", "extra", "Remove unsupported field: extra"},
		{"additional_properties", "", "Remove unsupported fields from the payload."},
	}

	for _, tt := range tests {
		t.Run(tt.code+"/"+tt.field, func(t *testing.T) {
			got := tr.deriveAction(tt.code, tt.field)
			if got != tt.want {
				t.Fatalf("deriveAction(%q, %q)=%q, want %q", tt.code, tt.field, got, tt.want)
			}
		})
	}
}

func TestTranslator_DeriveAction_UnknownCodeNoDefault(t *testing.T) {
	tr := NewTranslator(CodeSchemaViolation)
	got := tr.deriveAction("custom", "field")
	want := "Correct the schema violation in your YAML/JSON file."
	if got != want {
		t.Fatalf("deriveAction(custom)=%q, want %q", got, want)
	}
}

func TestTranslator_TranslateOne_EmptyFieldWithPrefix(t *testing.T) {
	tr := NewTranslator(CodeSchemaViolation, WithPathPrefix("obs.json"))
	issue := tr.TranslateOne(testExternalError{
		field: "",
		desc:  "invalid format",
		code:  "type",
	})
	path, ok := issue.Evidence.Get("path")
	if !ok || path != "obs.json" {
		t.Fatalf("path=%q ok=%v, want obs.json", path, ok)
	}
}

func TestTranslator_TranslateOne_EmptyFieldNoPrefix(t *testing.T) {
	tr := NewTranslator(CodeSchemaViolation)
	issue := tr.TranslateOne(testExternalError{
		field: "",
		desc:  "invalid format",
		code:  "type",
	})
	_, ok := issue.Evidence.Get("path")
	if ok {
		t.Fatal("path evidence should not be set when both field and prefix are empty")
	}
}

func TestTranslator_Translate_Empty(t *testing.T) {
	tr := NewTranslator(CodeSchemaViolation)
	result := tr.Translate(nil)
	if result == nil {
		t.Fatal("result should not be nil for empty input")
	}
	if len(result.Issues) != 0 {
		t.Fatalf("len=%d, want 0", len(result.Issues))
	}
}

func TestTranslator_Translate_Multiple(t *testing.T) {
	tr := NewTranslator(CodeSchemaViolation)
	result := tr.Translate([]ExternalError{
		testExternalError{field: "/a", desc: "err1", code: "required"},
		testExternalError{field: "/b", desc: "err2", code: "enum"},
	})
	if len(result.Issues) != 2 {
		t.Fatalf("len=%d, want 2", len(result.Issues))
	}
}
