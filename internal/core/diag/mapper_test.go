package diag

import "testing"

type testRawIssue struct {
	field string
	desc  string
	code  string
}

func (e testRawIssue) Field() string       { return e.field }
func (e testRawIssue) Description() string { return e.desc }
func (e testRawIssue) Code() string        { return e.code }

func TestTranslator_TranslateWithPrefix(t *testing.T) {
	translator := NewMapper(RuleSchemaViolation,
		WithDefaultRemediation("Fix input to match schema"),
		WithPathPrefix("controls.yaml"),
	)

	result := translator.Map([]RawIssue{
		testRawIssue{
			field: "/dsl_version",
			desc:  "missing required field",
			code:  "required",
		},
	})

	if result == nil || len(result.Findings) != 1 {
		t.Fatalf("finding count=%d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.RuleID != RuleSchemaViolation {
		t.Fatalf("rule_id=%q, want %q", finding.RuleID, RuleSchemaViolation)
	}
	if finding.Severity != SeverityError {
		t.Fatalf("severity=%q, want %q", finding.Severity, SeverityError)
	}
	if got := finding.Message; got != "missing required field" {
		t.Fatalf("message=%q, want %q", got, "missing required field")
	}
	if got := finding.Remediation; got == "" {
		t.Fatal("action should not be empty")
	}
	if path, ok := finding.Resource.Get("path"); !ok || path != "controls.yaml: /dsl_version" {
		t.Fatalf("path resource=%q ok=%v", path, ok)
	}
}

func TestTranslator_DefaultActionFallback(t *testing.T) {
	translator := NewMapper(RuleSchemaViolation,
		WithDefaultRemediation("Fix input to match schema"),
	)

	finding := translator.MapOne(testRawIssue{
		field: "/x",
		desc:  "unknown schema violation",
		code:  "custom",
	})

	if finding.Remediation != "Fix input to match schema" {
		t.Fatalf("action=%q, want fallback action", finding.Remediation)
	}
}
