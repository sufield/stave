package enginetest

import (
	"slices"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestControlDefinitionValidate_ValidControlHasNoIssues(t *testing.T) {
	ctl := validControlForValidationTests()

	issues := ctl.Validate()
	if len(issues) != 0 {
		t.Fatalf("validate() issues = %d, want 0: %#v", len(issues), issues)
	}
}

func TestControlDefinitionValidate_RequiredFields(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.ID = ""
	ctl.Name = ""
	ctl.Description = ""

	issues := ctl.Validate()
	if len(issues) != 3 {
		t.Fatalf("validate() issues = %d, want 3", len(issues))
	}

	assertIssueCodeAndSignal(t, issues[0], diag.RuleControlMissingID, diag.SeverityError)
	assertIssueCodeAndSignal(t, issues[1], diag.RuleControlMissingName, diag.SeverityError)
	assertIssueCodeAndSignal(t, issues[2], diag.RuleControlMissingDesc, diag.SeverityError)
}

func TestControlDefinitionValidate_BadIDFormatWarningIncludesSensitiveError(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.ID = "not-an-control-id"

	issues := ctl.Validate()
	if len(issues) != 1 {
		t.Fatalf("validate() issues = %d, want 1", len(issues))
	}

	issue := issues[0]
	assertIssueCodeAndSignal(t, issue, diag.RuleControlBadIDFormat, diag.SeverityWarn)

	if got, ok := issue.Resource.Get("control_id"); !ok || got != ctl.ID.String() {
		t.Fatalf("evidence control_id = %q (ok=%v), want %q", got, ok, ctl.ID)
	}
	if got := issue.Resource.Sanitized("error"); got != kernel.Redacted {
		t.Fatalf("sanitized error = %q, want %q", got, kernel.Redacted)
	}
	rawErr, ok := issue.Resource.Get("error")
	if !ok {
		t.Fatalf("expected raw error evidence key")
	}
	if !strings.Contains(rawErr, "invalid control ID") {
		t.Fatalf("raw error = %q, expected format error text", rawErr)
	}
}

func TestControlDefinitionValidate_BadTypeWarning(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.Type = policy.ControlType(999)

	issues := ctl.Validate()
	if len(issues) != 1 {
		t.Fatalf("validate() issues = %d, want 1", len(issues))
	}

	issue := issues[0]
	assertIssueCodeAndSignal(t, issue, diag.RuleControlBadType, diag.SeverityWarn)

	if got, ok := issue.Resource.Get("type"); !ok || got != "unknown" {
		t.Fatalf("evidence type = %q (ok=%v), want %q for unknown type", got, ok, "unknown")
	}
	if !strings.Contains(issue.Remediation, "supported control type") {
		t.Fatalf("action = %q, want supported type hint", issue.Remediation)
	}
}

func TestControlDefinitionValidate_EmptyPredicateWarning(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.UnsafePredicate = policy.UnsafePredicate{}

	issues := ctl.Validate()
	if len(issues) != 1 {
		t.Fatalf("validate() issues = %d, want 1", len(issues))
	}

	assertIssueCodeAndSignal(t, issues[0], diag.RuleControlEmptyPredicate, diag.SeverityWarn)
}

func TestControlDefinitionValidate_UndefinedParamReferencesAreUniqueAndSorted(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.UnsafePredicate = policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, ValueFromParam: predicate.ParamRef("p2")},
			{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.acl"), Op: predicate.OpEq, ValueFromParam: predicate.ParamRef("p1")},
					{Field: predicate.NewFieldPath("properties.owner"), Op: predicate.OpEq, ValueFromParam: predicate.ParamRef("p2")},
				},
			},
		},
	}
	ctl.Params = policy.NewParams(map[string]any{
		"defined_param": true,
	})

	issues := ctl.Validate()
	if len(issues) != 2 {
		t.Fatalf("validate() issues = %d, want 2", len(issues))
	}

	gotParams := make([]string, 0, len(issues))
	for _, issue := range issues {
		assertIssueCodeAndSignal(t, issue, diag.RuleControlUndefinedParam, diag.SeverityError)
		param, ok := issue.Resource.Get("param")
		if !ok {
			t.Fatalf("undefined param issue missing evidence.param")
		}
		gotParams = append(gotParams, param)
	}

	wantParams := []string{"p1", "p2"}
	if !slices.Equal(gotParams, wantParams) {
		t.Fatalf("undefined param order = %v, want %v", gotParams, wantParams)
	}
}

func TestControlDefinitionValidate_MaxUnsafeDurationParam(t *testing.T) {
	tests := []struct {
		name                string
		params              policy.ControlParams
		wantIssueCount      int
		wantSensitiveErrKey bool
	}{
		{
			name:           "param absent",
			params:         policy.ControlParams{},
			wantIssueCount: 0,
		},
		{
			name: "param valid duration",
			params: policy.NewParams(map[string]any{
				"max_unsafe_duration": "24h",
			}),
			wantIssueCount: 0,
		},
		{
			name: "param empty string",
			params: policy.NewParams(map[string]any{
				"max_unsafe_duration": "",
			}),
			wantIssueCount: 1,
		},
		{
			name: "param non string",
			params: policy.NewParams(map[string]any{
				"max_unsafe_duration": 24,
			}),
			wantIssueCount: 1,
		},
		{
			name: "param invalid duration",
			params: policy.NewParams(map[string]any{
				"max_unsafe_duration": "bad-duration",
			}),
			wantIssueCount:      1,
			wantSensitiveErrKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl := validControlForValidationTests()
			ctl.Params = tt.params

			issues := ctl.Validate()
			if len(issues) != tt.wantIssueCount {
				t.Fatalf("validate() issues = %d, want %d", len(issues), tt.wantIssueCount)
			}
			if tt.wantIssueCount == 0 {
				return
			}

			issue := issues[0]
			assertIssueCodeAndSignal(t, issue, diag.RuleControlBadDurationParam, diag.SeverityError)

			if got, ok := issue.Resource.Get("param"); !ok || got != "max_unsafe_duration" {
				t.Fatalf("evidence param = %q (ok=%v), want %q", got, ok, "max_unsafe_duration")
			}

			if tt.wantSensitiveErrKey {
				if got := issue.Resource.Sanitized("error"); got != kernel.Redacted {
					t.Fatalf("sanitized error = %q, want %q", got, kernel.Redacted)
				}
				if raw, ok := issue.Resource.Get("error"); !ok || raw == "" {
					t.Fatalf("expected raw sensitive error key to be set")
				}
			}
		})
	}
}

func validControlForValidationTests() policy.ControlDefinition {
	return policy.ControlDefinition{
		ID:          "CTL.S3.PUBLIC.001",
		Name:        "Public bucket",
		Description: "Bucket must not be publicly exposed",
		Type:        policy.TypeUnsafeState,
		Params:      policy.ControlParams{},
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{
					Field: predicate.NewFieldPath("properties.public"),
					Op:    "eq",
					Value: policy.Bool(true),
				},
			},
		},
	}
}

func assertIssueCodeAndSignal(t *testing.T, issue diag.Finding, wantCode diag.RuleID, wantSignal diag.Severity) {
	t.Helper()
	if issue.RuleID != wantCode {
		t.Fatalf("issue code = %q, want %q", issue.RuleID, wantCode)
	}
	if issue.Severity != wantSignal {
		t.Fatalf("issue signal = %q, want %q", issue.Severity, wantSignal)
	}
}
