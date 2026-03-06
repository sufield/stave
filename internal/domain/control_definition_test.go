package domain

import (
	"slices"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestControlDefinitionValidate_ValidControlHasNoIssues(t *testing.T) {
	ctl := validControlForValidationTests()

	issues := policy.ValidateControlDefinition(&ctl)
	if len(issues) != 0 {
		t.Fatalf("validate() issues = %d, want 0: %#v", len(issues), issues)
	}
}

func TestControlDefinitionValidate_RequiredFields(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.ID = ""
	ctl.Name = ""
	ctl.Description = ""

	issues := policy.ValidateControlDefinition(&ctl)
	if len(issues) != 3 {
		t.Fatalf("validate() issues = %d, want 3", len(issues))
	}

	assertIssueCodeAndSignal(t, issues[0], diag.CodeControlMissingID, diag.SignalError)
	assertIssueCodeAndSignal(t, issues[1], diag.CodeControlMissingName, diag.SignalError)
	assertIssueCodeAndSignal(t, issues[2], diag.CodeControlMissingDesc, diag.SignalError)
}

func TestControlDefinitionValidate_BadIDFormatWarningIncludesSensitiveError(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.ID = "not-an-control-id"

	issues := policy.ValidateControlDefinition(&ctl)
	if len(issues) != 1 {
		t.Fatalf("validate() issues = %d, want 1", len(issues))
	}

	issue := issues[0]
	assertIssueCodeAndSignal(t, issue, diag.CodeControlBadIDFormat, diag.SignalWarn)

	if got, ok := issue.Evidence.Get("control_id"); !ok || got != ctl.ID.String() {
		t.Fatalf("evidence control_id = %q (ok=%v), want %q", got, ok, ctl.ID)
	}
	if got := issue.Evidence.Sanitized("error"); got != kernel.SanitizedValue {
		t.Fatalf("sanitized error = %q, want %q", got, kernel.SanitizedValue)
	}
	rawErr, ok := issue.Evidence.Get("error")
	if !ok {
		t.Fatalf("expected raw error evidence key")
	}
	if !strings.Contains(rawErr, "invalid control ID format") {
		t.Fatalf("raw error = %q, expected format error text", rawErr)
	}
}

func TestControlDefinitionValidate_BadTypeWarning(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.Type = policy.ControlType(999)

	issues := policy.ValidateControlDefinition(&ctl)
	if len(issues) != 1 {
		t.Fatalf("validate() issues = %d, want 1", len(issues))
	}

	issue := issues[0]
	assertIssueCodeAndSignal(t, issue, diag.CodeControlBadType, diag.SignalWarn)

	if got, ok := issue.Evidence.Get("type"); !ok || got != "" {
		t.Fatalf("evidence type = %q (ok=%v), want empty string for unknown type", got, ok)
	}
	if !strings.Contains(issue.Action, "Use a canonical type:") {
		t.Fatalf("action = %q, want canonical type hint", issue.Action)
	}
}

func TestControlDefinitionValidate_EmptyPredicateWarning(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.UnsafePredicate = policy.UnsafePredicate{}

	issues := policy.ValidateControlDefinition(&ctl)
	if len(issues) != 1 {
		t.Fatalf("validate() issues = %d, want 1", len(issues))
	}

	assertIssueCodeAndSignal(t, issues[0], diag.CodeControlEmptyPredicate, diag.SignalWarn)
}

func TestControlDefinitionValidate_UndefinedParamReferencesAreUniqueAndSorted(t *testing.T) {
	ctl := validControlForValidationTests()
	ctl.UnsafePredicate = policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{Field: "properties.public", Op: "eq", ValueFromParam: "p2"},
			{
				All: []policy.PredicateRule{
					{Field: "properties.acl", Op: "eq", ValueFromParam: "p1"},
					{Field: "properties.owner", Op: "eq", ValueFromParam: "p2"},
				},
			},
		},
	}
	ctl.Params = policy.ControlParams{
		"defined_param": true,
	}

	issues := policy.ValidateControlDefinition(&ctl)
	if len(issues) != 2 {
		t.Fatalf("validate() issues = %d, want 2", len(issues))
	}

	gotParams := make([]string, 0, len(issues))
	for _, issue := range issues {
		assertIssueCodeAndSignal(t, issue, diag.CodeControlUndefinedParam, diag.SignalError)
		param, ok := issue.Evidence.Get("param")
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
			params: policy.ControlParams{
				"max_unsafe_duration": "24h",
			},
			wantIssueCount: 0,
		},
		{
			name: "param empty string",
			params: policy.ControlParams{
				"max_unsafe_duration": "",
			},
			wantIssueCount: 1,
		},
		{
			name: "param non string",
			params: policy.ControlParams{
				"max_unsafe_duration": 24,
			},
			wantIssueCount: 1,
		},
		{
			name: "param invalid duration",
			params: policy.ControlParams{
				"max_unsafe_duration": "bad-duration",
			},
			wantIssueCount:      1,
			wantSensitiveErrKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl := validControlForValidationTests()
			ctl.Params = tt.params

			issues := policy.ValidateControlDefinition(&ctl)
			if len(issues) != tt.wantIssueCount {
				t.Fatalf("validate() issues = %d, want %d", len(issues), tt.wantIssueCount)
			}
			if tt.wantIssueCount == 0 {
				return
			}

			issue := issues[0]
			assertIssueCodeAndSignal(t, issue, diag.CodeControlBadDurationParam, diag.SignalError)

			if got, ok := issue.Evidence.Get("param"); !ok || got != "max_unsafe_duration" {
				t.Fatalf("evidence param = %q (ok=%v), want %q", got, ok, "max_unsafe_duration")
			}

			if tt.wantSensitiveErrKey {
				if got := issue.Evidence.Sanitized("error"); got != kernel.SanitizedValue {
					t.Fatalf("sanitized error = %q, want %q", got, kernel.SanitizedValue)
				}
				if raw, ok := issue.Evidence.Get("error"); !ok || raw == "" {
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
					Field: "properties.public",
					Op:    "eq",
					Value: true,
				},
			},
		},
	}
}

func assertIssueCodeAndSignal(t *testing.T, issue diag.Issue, wantCode string, wantSignal diag.Signal) {
	t.Helper()
	if issue.Code != wantCode {
		t.Fatalf("issue code = %q, want %q", issue.Code, wantCode)
	}
	if issue.Signal != wantSignal {
		t.Fatalf("issue signal = %q, want %q", issue.Signal, wantSignal)
	}
}
