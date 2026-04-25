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
	catalog := map[kernel.ControlID]bool{"CTL.A.001": true, "CTL.B.001": true}
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
	catalog := map[kernel.ControlID]bool{"CTL.A.001": true}
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
