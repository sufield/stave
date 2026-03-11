package diag

import "testing"

type testExternalError struct {
	field string
	desc  string
	code  string
}

func (e testExternalError) Field() string       { return e.field }
func (e testExternalError) Description() string { return e.desc }
func (e testExternalError) Code() string        { return e.code }

func TestTranslator_TranslateWithPrefix(t *testing.T) {
	translator := NewTranslator(CodeSchemaViolation,
		WithDefaultAction("Fix input to match schema"),
		WithPathPrefix("controls.yaml"),
	)

	result := translator.Translate([]ExternalError{
		testExternalError{
			field: "/dsl_version",
			desc:  "missing required field",
			code:  "required",
		},
	})

	if result == nil || len(result.Issues) != 1 {
		t.Fatalf("issue count=%d, want 1", len(result.Issues))
	}
	issue := result.Issues[0]
	if issue.Code != CodeSchemaViolation {
		t.Fatalf("code=%q, want %q", issue.Code, CodeSchemaViolation)
	}
	if issue.Signal != SignalError {
		t.Fatalf("signal=%q, want %q", issue.Signal, SignalError)
	}
	if got := issue.Message; got != "missing required field" {
		t.Fatalf("message=%q, want %q", got, "missing required field")
	}
	if got := issue.Action; got == "" {
		t.Fatal("action should not be empty")
	}
	if path, ok := issue.Evidence.Get("path"); !ok || path != "controls.yaml: /dsl_version" {
		t.Fatalf("path evidence=%q ok=%v", path, ok)
	}
}

func TestTranslator_DefaultActionFallback(t *testing.T) {
	translator := NewTranslator(CodeSchemaViolation,
		WithDefaultAction("Fix input to match schema"),
	)

	issue := translator.TranslateOne(testExternalError{
		field: "/x",
		desc:  "unknown schema violation",
		code:  "custom",
	})

	if issue.Action != "Fix input to match schema" {
		t.Fatalf("action=%q, want fallback action", issue.Action)
	}
}
