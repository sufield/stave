package diag

import "testing"

func TestNewTranslator_EmptyDefaultRule(t *testing.T) {
	tr := NewTranslator("")
	if tr.defaultRule != RuleSchemaViolation {
		t.Fatalf("empty default rule should fallback to %q, got %q", RuleSchemaViolation, tr.defaultRule)
	}
}

func TestNewTranslator_WhitespaceDefaultRule(t *testing.T) {
	tr := NewTranslator("  ")
	if tr.defaultRule != RuleSchemaViolation {
		t.Fatalf("whitespace default rule should fallback to %q, got %q", RuleSchemaViolation, tr.defaultRule)
	}
}

func TestNewTranslator_CustomRule(t *testing.T) {
	tr := NewTranslator(RuleControlLoadFailed)
	if tr.defaultRule != RuleControlLoadFailed {
		t.Fatalf("defaultRule=%q, want %q", tr.defaultRule, RuleControlLoadFailed)
	}
}

func TestTranslator_MapRule_KnownCodes(t *testing.T) {
	tr := NewTranslator(RuleControlLoadFailed)
	knownCodes := []string{"required", "type", "enum", "additional_properties"}
	for _, code := range knownCodes {
		got := tr.mapRule(code)
		if got != RuleSchemaViolation {
			t.Fatalf("mapRule(%q)=%q, want %q", code, got, RuleSchemaViolation)
		}
	}
}

func TestTranslator_MapRule_UnknownCode(t *testing.T) {
	tr := NewTranslator(RuleControlLoadFailed)
	got := tr.mapRule("something_else")
	if got != RuleControlLoadFailed {
		t.Fatalf("mapRule(unknown)=%q, want %q", got, RuleControlLoadFailed)
	}
}

func TestTranslator_DeriveAction_AllKnownCodes(t *testing.T) {
	tr := NewTranslator(RuleSchemaViolation)

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
	tr := NewTranslator(RuleSchemaViolation)
	got := tr.deriveAction("custom", "field")
	want := "Correct the schema violation in your YAML/JSON file."
	if got != want {
		t.Fatalf("deriveAction(custom)=%q, want %q", got, want)
	}
}

func TestTranslator_TranslateOne_EmptyFieldWithPrefix(t *testing.T) {
	tr := NewTranslator(RuleSchemaViolation, WithPathPrefix("obs.json"))
	finding := tr.TranslateOne(testExternalError{
		field: "",
		desc:  "invalid format",
		code:  "type",
	})
	path, ok := finding.Resource.Get("path")
	if !ok || path != "obs.json" {
		t.Fatalf("path=%q ok=%v, want obs.json", path, ok)
	}
}

func TestTranslator_TranslateOne_EmptyFieldNoPrefix(t *testing.T) {
	tr := NewTranslator(RuleSchemaViolation)
	finding := tr.TranslateOne(testExternalError{
		field: "",
		desc:  "invalid format",
		code:  "type",
	})
	_, ok := finding.Resource.Get("path")
	if ok {
		t.Fatal("path resource should not be set when both field and prefix are empty")
	}
}

func TestTranslator_Translate_Empty(t *testing.T) {
	tr := NewTranslator(RuleSchemaViolation)
	result := tr.Translate(nil)
	if result == nil {
		t.Fatal("result should not be nil for empty input")
	}
	if len(result.Findings) != 0 {
		t.Fatalf("len=%d, want 0", len(result.Findings))
	}
}

func TestTranslator_Translate_Multiple(t *testing.T) {
	tr := NewTranslator(RuleSchemaViolation)
	result := tr.Translate([]ExternalError{
		testExternalError{field: "/a", desc: "err1", code: "required"},
		testExternalError{field: "/b", desc: "err2", code: "enum"},
	})
	if len(result.Findings) != 2 {
		t.Fatalf("len=%d, want 2", len(result.Findings))
	}
}
