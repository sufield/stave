package chainforge

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// testRegistry is the test-local capability vocabulary. Tests do not
// depend on the catalog layer's real registry — they declare exactly
// the capabilities they exercise.
var testRegistry = policy.CapabilitySet{
	"internet_access":      {},
	"iam_credential_theft": {},
}

func TestLintChain_ValidChain(t *testing.T) {
	chain := &policy.ChainDefinition{
		ID:                  "test_chain",
		Description:         "test",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		EscalationThreshold: 2,
		Preconditions:       []string{"internet_access"},
		Postconditions:      []string{"iam_credential_theft"},
	}
	catalog := map[kernel.ControlID]struct{}{"CTL.A.001": {}, "CTL.B.001": {}}
	result := LintChain(chain, catalog, testRegistry)
	if len(result.Errors) != 0 {
		t.Errorf("valid chain should have 0 errors, got %d: %v", len(result.Errors), result.Errors)
	}
}

func TestLintChain_UnknownControl(t *testing.T) {
	chain := &policy.ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.UNKNOWN.001"},
		EscalationThreshold: 2,
	}
	catalog := map[kernel.ControlID]struct{}{"CTL.A.001": {}}
	result := LintChain(chain, catalog, testRegistry)
	hasError := false
	for _, e := range result.Errors {
		if e == `member control "CTL.UNKNOWN.001" not found in catalog` {
			hasError = true
		}
	}
	if !hasError {
		t.Errorf("should detect unknown control, errors: %v", result.Errors)
	}
}

func TestLintChain_InvalidCapability(t *testing.T) {
	chain := &policy.ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		EscalationThreshold: 2,
		Preconditions:       []string{"totally_fake_capability"},
	}
	result := LintChain(chain, nil, testRegistry)
	hasError := false
	for _, e := range result.Errors {
		if e == `precondition "totally_fake_capability" is not a valid capability` {
			hasError = true
		}
	}
	if !hasError {
		t.Errorf("should detect invalid capability, errors: %v", result.Errors)
	}
}

func TestLintChain_ImplicitDependency_EmptySource(t *testing.T) {
	chain := &policy.ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		EscalationThreshold: 2,
		ImplicitDependencies: []policy.ImplicitDependency{
			{Source: "", Fallback: policy.FallbackFailClosed, Diagnostic: "msg"},
		},
	}
	result := LintChain(chain, nil, nil)
	hasError := false
	for _, e := range result.Errors {
		if e == "implicit_dependencies[0]: source is required" {
			hasError = true
		}
	}
	if !hasError {
		t.Errorf("should detect empty source, errors: %v", result.Errors)
	}
}

func TestLintChain_ImplicitDependency_InvalidFallback(t *testing.T) {
	chain := &policy.ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		EscalationThreshold: 2,
		ImplicitDependencies: []policy.ImplicitDependency{
			{Source: "some.source", Fallback: "bogus"},
		},
	}
	result := LintChain(chain, nil, nil)
	hasError := false
	for _, e := range result.Errors {
		if e == `implicit_dependencies[0]: invalid fallback "bogus" (must be fail_closed, fail_open, or cross_validate)` {
			hasError = true
		}
	}
	if !hasError {
		t.Errorf("should detect invalid fallback, errors: %v", result.Errors)
	}
}

func TestLintChain_ImplicitDependency_FailClosedRequiresDiagnostic(t *testing.T) {
	chain := &policy.ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		EscalationThreshold: 2,
		ImplicitDependencies: []policy.ImplicitDependency{
			{Source: "some.source", Fallback: policy.FallbackFailClosed, Diagnostic: ""},
		},
	}
	result := LintChain(chain, nil, nil)
	hasError := false
	for _, e := range result.Errors {
		if e == `implicit_dependencies[0]: diagnostic is required when fallback is "fail_closed"` {
			hasError = true
		}
	}
	if !hasError {
		t.Errorf("should require diagnostic for fail_closed, errors: %v", result.Errors)
	}
}

func TestLintChain_ImplicitDependency_FailOpenWarns(t *testing.T) {
	chain := &policy.ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
		EscalationThreshold: 2,
		ImplicitDependencies: []policy.ImplicitDependency{
			{Source: "some.source", Fallback: policy.FallbackFailOpen},
		},
	}
	result := LintChain(chain, nil, nil)
	if len(result.Errors) != 0 {
		t.Errorf("fail_open should not produce errors, got: %v", result.Errors)
	}
	hasWarning := false
	for _, w := range result.Warnings {
		if w == `implicit_dependencies[0]: fallback is fail_open (source "some.source") — verify this is intentional` {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Errorf("should warn about fail_open, warnings: %v", result.Warnings)
	}
}
