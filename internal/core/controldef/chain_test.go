package controldef

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestChainDefinition_Validate(t *testing.T) {
	valid := ChainDefinition{
		ID:                  "public_phi_exposure",
		Description:         "PHI data reachable from public internet",
		ControlIDs:          []kernel.ControlID{"CTL.S3.PUBLIC.001", "CTL.S3.ENCRYPT.001"},
		EscalationThreshold: 2,
		CompoundSeverity:    SeverityCritical,
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid chain failed: %v", err)
	}

	tests := []struct {
		name  string
		chain ChainDefinition
		want  string
	}{
		{"missing id", ChainDefinition{ControlIDs: []kernel.ControlID{"A", "B"}, EscalationThreshold: 1}, "missing id"},
		{"too few controls", ChainDefinition{ID: "x", ControlIDs: []kernel.ControlID{"A"}, EscalationThreshold: 1}, "at least 2"},
		{"threshold zero", ChainDefinition{ID: "x", ControlIDs: []kernel.ControlID{"A", "B"}, EscalationThreshold: 0}, "must be >= 1"},
		{"threshold exceeds", ChainDefinition{ID: "x", ControlIDs: []kernel.ControlID{"A", "B"}, EscalationThreshold: 5}, "escalation_threshold (5) > control count (2)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.chain.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsStr(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestChainDefinition_Validate_ValidCapabilities(t *testing.T) {
	c := ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.A.002"},
		EscalationThreshold: 2,
		CompoundSeverity:    SeverityHigh,
		Preconditions:       []string{"internet_access"},
		Postconditions:      []string{"iam_credential_theft", "network_access_ec2"},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("valid chain should pass: %v", err)
	}
}

func TestChainDefinition_Validate_InvalidCapability(t *testing.T) {
	c := ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.A.002"},
		EscalationThreshold: 2,
		CompoundSeverity:    SeverityHigh,
		Preconditions:       []string{"totally_fake_capability"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid precondition capability")
	}

	c2 := ChainDefinition{
		ID:                  "test_chain",
		ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.A.002"},
		EscalationThreshold: 2,
		CompoundSeverity:    SeverityHigh,
		Postconditions:      []string{"nonexistent_cap"},
	}
	if err := c2.Validate(); err == nil {
		t.Fatal("expected error for invalid postcondition capability")
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
